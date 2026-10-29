//! Sparse post-state roots, with upserts before removals as in zeth and canonical reth witnesses.

use super::TrieAccount;
use crate::constants::EMPTY_ROOT_HASH;
use crate::crypto::keccak256;
use crate::witness_backend::{RevealedAccount, WitnessAccount, WitnessState};
use aurora_evm_trie::sparse::{NodeStore, PatchError, PatchTrie};
use core::fmt;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeSet;

/// Computes the post-state root from the original witness and execution's recorded writes.
///
/// Read-only accounts and slots are skipped. A single storage overlay and RLP buffer are reused
/// across accounts; untouched subtrees keep their witness hashes. Empty-account pruning belongs
/// to execution, not this function. The input state is unchanged, including on failure.
///
/// # Errors
/// [`StateRootError`] for a missing trie, missing/malformed proof nodes (including collapse
/// siblings), or an inconsistent internal changeset. Materialized maps need [`super::state_root`].
///
/// # Panics
/// Panics if an internal RLP encoder violates its list arity or the trie encoder's invariants.
pub fn witness_state_root(state: &WitnessState) -> Result<H256, StateRootError> {
    let trie = state.trie.as_ref().ok_or(StateRootError::NoTrie)?;
    if state.changes.is_empty() {
        return Ok(trie.state_root());
    }
    let mut accounts = PatchTrie::new(trie.nodes(), trie.state_root().0);
    let mut storage = None;
    let mut scratch = None;

    // Upserts first avoid transient branch collapses requiring extra witness nodes.
    for (address, slots) in &state.changes {
        let account = state
            .accounts
            .get(address)
            .ok_or(StateRootError::MissingAccount(*address))?;
        let RevealedAccount::Present(account) = account else {
            continue;
        };
        // Deletion-only changes need neither leaf-encoding scratch nor a storage overlay.
        let stream = scratch.get_or_insert_with(rlp::RlpStream::new);
        let storage_root =
            account_storage_root(&mut storage, trie.nodes(), stream, *address, account, slots)?;
        stream.clear();
        stream.append(&TrieAccount {
            nonce: account.nonce,
            balance: account.balance,
            storage_root,
            code_hash: account.code_hash,
            code_version: U256::zero(),
        });
        // as_raw() bypasses out()'s release check; never hash an unfinished account list.
        assert!(
            stream.is_finished(),
            "account encoder left an open RLP list"
        );
        accounts.insert(&keccak256(address.as_bytes()).0, stream.as_raw())?;
    }

    for address in state.changes.keys() {
        if matches!(state.accounts.get(address), Some(RevealedAccount::Absent)) {
            accounts.remove(&keccak256(address.as_bytes()).0)?;
        }
    }

    Ok(H256(accounts.root_hash()?))
}

/// Patches written slots only; a wipe starts from the empty root without opening old storage.
fn account_storage_root<'store>(
    patch: &mut Option<PatchTrie<'store>>,
    nodes: &'store NodeStore,
    stream: &mut rlp::RlpStream,
    address: H160,
    account: &WitnessAccount,
    slots: &BTreeSet<H256>,
) -> Result<H256, StateRootError> {
    let root = if account.storage_wiped {
        EMPTY_ROOT_HASH
    } else {
        account.storage_root
    };
    if slots.is_empty() {
        return Ok(root);
    }

    let patch = patch.get_or_insert_with(|| PatchTrie::new(nodes, root.0));
    patch.reset(root.0);
    for slot in slots {
        let value = account
            .storage
            .get(slot)
            .ok_or(StateRootError::MissingStorageSlot {
                address,
                slot: *slot,
            })?;

        if !value.is_zero() {
            stream.clear();
            stream.append(&U256::from_big_endian(value.as_bytes()));
            patch.insert(&keccak256(slot.as_bytes()).0, stream.as_raw())?;
        }
    }

    for slot in slots {
        if account.storage.get(slot).is_some_and(H256::is_zero) {
            patch.remove(&keccak256(slot.as_bytes()).0)?;
        }
    }

    Ok(H256(patch.root_hash()?))
}

/// Sparse root reconstruction failed; no candidate root is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateRootError {
    /// The state came from materialized maps rather than a witness-backed backend.
    NoTrie,
    /// Missing/malformed witness nodes, or an empty value from an internal encoder.
    /// `PatchError::EmptyValue` is an encoder invariant failure, not missing witness data.
    Patch(PatchError),
    /// An internal changeset refers to an account absent from the revealed map.
    MissingAccount(H160),
    /// An internal changeset refers to a slot absent from the account's cached storage.
    MissingStorageSlot {
        /// Changed account.
        address: H160,
        /// Changed storage key.
        slot: H256,
    },
}

impl From<PatchError> for StateRootError {
    fn from(error: PatchError) -> Self {
        Self::Patch(error)
    }
}

impl fmt::Display for StateRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrie => f.write_str("state has no witness trie"),
            Self::Patch(error) => write!(f, "post-state trie update failed: {error}"),
            Self::MissingAccount(address) => write!(f, "changed account {address:?} is not cached"),
            Self::MissingStorageSlot { address, slot } => write!(
                f,
                "changed slot {slot:?} of account {address:?} is not cached"
            ),
        }
    }
}

impl core::error::Error for StateRootError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Patch(error) => Some(error),
            _ => None,
        }
    }
}
