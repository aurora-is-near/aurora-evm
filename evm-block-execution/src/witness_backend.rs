//! Witness-backed state with lazy account and storage proofs.
//!
//! Proven absence differs from missing data; account code hashes are stored separately from code.
//! Unproved reads return defaults and record the first [`WitnessDbError`]. Reject execution if
//! [`WitnessBackend::missing`] is set, or use [`WitnessBackend::try_into_state`] to enforce this.
//! Counterpart of reth's `WitnessDatabase`, behind the `aurora_evm` [`Backend`] trait.

use crate::constants::{BLOCKHASH_WINDOW, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use crate::crypto::keccak256;
use crate::execution_types::witness::ExecutionWitness;
use crate::trie::{TrieAccount, storage_root};
use aurora_evm::backend::{
    Apply, ApplyBackend, Backend, Basic, Log, MemoryAccount, MemoryVicinity,
};
use aurora_evm_trie::sparse::{LookupError, NodeStore};
use core::cell::{Cell, Ref, RefCell};
use core::fmt;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

/// An account's proven fields and cached storage, independent of available code bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessAccount {
    /// Account nonce.
    pub nonce: U256,
    /// Account balance.
    pub balance: U256,
    /// Code hash from the account's trie leaf. `KECCAK_EMPTY` for an account with no code.
    pub code_hash: H256,
    /// Root used to prove uncached slots; not recomputed after execution writes.
    /// Treat unlisted slots as zero when `storage_wiped || storage_root == EMPTY_ROOT_HASH`;
    /// otherwise resolve them against this root. Cached writes take precedence.
    pub storage_root: H256,
    /// Resolved slots and execution writes, including explicit zeros.
    /// Unlisted slots need a proof unless storage is known empty or wiped.
    pub storage: BTreeMap<H256, H256>,
    /// Whether storage was reset; unlisted slots are then zero regardless of `storage_root`.
    pub storage_wiped: bool,
}

impl WitnessAccount {
    /// An account with no nonce, balance, code or storage.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            nonce: U256::zero(),
            balance: U256::zero(),
            code_hash: KECCAK_EMPTY,
            storage_root: EMPTY_ROOT_HASH,
            storage: BTreeMap::new(),
            storage_wiped: false,
        }
    }

    /// Whether `code_hash` indicates code, even if its bytes are unavailable.
    #[must_use]
    pub fn has_code(&self) -> bool {
        self.code_hash != KECCAK_EMPTY
    }

    /// Whether the account is "empty" in the EIP-161 sense: zero nonce, zero balance, no code.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nonce.is_zero() && self.balance.is_zero() && !self.has_code()
    }

    /// Whether every slot is zero — the account started with empty storage (or it was wiped) and
    /// nothing non-zero has been written since.
    #[must_use]
    pub fn is_storage_empty(&self) -> bool {
        (self.storage_wiped || self.storage_root == EMPTY_ROOT_HASH)
            && self.storage.values().all(H256::is_zero)
    }

    /// Whether an unlisted slot of this account is provably zero without consulting the trie.
    fn unlisted_slots_are_zero(&self) -> bool {
        self.storage_wiped || self.storage_root == EMPTY_ROOT_HASH
    }
}

/// A proven account or proven absence; an unlisted address remains unresolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevealedAccount {
    /// The trie proved the account exists, with these fields.
    Present(WitnessAccount),
    /// The trie proved the account does not exist. Reads are zero, and that is a *proven* zero.
    Absent,
}

/// How reads outside the resolved maps are interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Coverage {
    /// Only revealed data is proven; anything else is a witness gap.
    Partial,
    /// The maps are the whole state: an address or slot they lack is provably absent.
    Complete,
}

/// The witness's trie nodes and the root they are proven against.
#[derive(Clone, Debug)]
struct RevealedTrie {
    nodes: NodeStore,
    state_root: H256,
}

impl RevealedTrie {
    /// Resolves the account leaf of `address`, or its proven absence.
    fn account(&self, address: H160) -> Result<RevealedAccount, WitnessDbError> {
        let key = keccak256(address.as_bytes());
        match self.nodes.get(self.state_root.0, key.as_bytes()) {
            Ok(None) => Ok(RevealedAccount::Absent),
            Ok(Some(leaf)) => {
                let account: TrieAccount =
                    rlp::decode(leaf).map_err(|_| WitnessDbError::Leaf { address })?;
                Ok(RevealedAccount::Present(WitnessAccount {
                    nonce: account.nonce,
                    balance: account.balance,
                    code_hash: account.code_hash,
                    storage_root: account.storage_root,
                    storage: BTreeMap::new(),
                    storage_wiped: false,
                }))
            }
            Err(error) => Err(trie_node_error(error)),
        }
    }

    /// Resolves `slot` in the storage trie at `storage_root`; an absent leaf is a proven zero.
    fn slot(&self, address: H160, storage_root: H256, slot: H256) -> Result<H256, WitnessDbError> {
        let key = keccak256(slot.as_bytes());
        match self.nodes.get(storage_root.0, key.as_bytes()) {
            Ok(None) => Ok(H256::zero()),
            Ok(Some(leaf)) => {
                let value: U256 =
                    rlp::decode(leaf).map_err(|_| WitnessDbError::Leaf { address })?;
                Ok(H256(value.to_big_endian()))
            }
            Err(error) => Err(trie_node_error(error)),
        }
    }
}

const fn trie_node_error(error: LookupError) -> WitnessDbError {
    match error {
        LookupError::BlindedNode(hash) | LookupError::MalformedNode(hash) => {
            WitnessDbError::TrieNode { hash: H256(hash) }
        }
    }
}

/// A storage read that could not be answered from the account's cached slots.
enum Slot {
    Value(H256),
    Zero,
    Unresolved(H256),
}

/// The post-state execution leaves behind; either map may be partial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessState {
    /// Every account execution revealed or touched, as it left them.
    pub accounts: BTreeMap<H160, RevealedAccount>,
    /// Code bytes keyed by hash, including code created by execution.
    pub codes: BTreeMap<H256, Vec<u8>>,
}

/// An EVM backend with lazy witness proofs and an owned execution environment.
#[derive(Clone, Debug)]
pub struct WitnessBackend {
    vicinity: MemoryVicinity,
    /// Accounts cached through shared [`Backend`] reads.
    accounts: RefCell<BTreeMap<H160, RevealedAccount>>,
    /// Code bytes keyed by `keccak256` of themselves — the hash an account's leaf refers to.
    codes: BTreeMap<H256, Vec<u8>>,
    /// Ancestor hashes by number; missing in-window entries remain detectable.
    ancestor_hashes: BTreeMap<u64, H256>,
    /// The trie unresolved reads are proven against, when the backend was built from a witness.
    trie: Option<RevealedTrie>,
    coverage: Coverage,
    /// The first read that had no proof, if any.
    missing: Cell<Option<WitnessDbError>>,
    logs: Vec<Log>,
}

impl WitnessBackend {
    /// Builds a backend from accounts proven against the parent root and verified ancestors.
    /// Unlisted accounts are witness gaps. Code bytes are indexed by their computed hashes.
    ///
    /// # Errors
    /// [`WitnessStateError::StorageContradictsRoot`] for nonzero slots under an empty root.
    pub fn try_new(
        vicinity: MemoryVicinity,
        accounts: BTreeMap<H160, RevealedAccount>,
        codes: Vec<Vec<u8>>,
        ancestor_hashes: BTreeMap<u64, H256>,
    ) -> Result<Self, WitnessStateError> {
        for (address, revealed) in &accounts {
            if let RevealedAccount::Present(account) = revealed {
                // An empty storage root says every slot is zero, and `storage()` relies on that to
                // answer an unlisted slot with a proven zero instead of poisoning. A non-zero slot
                // filed under such a root would turn that shortcut into a silent wrong answer.
                if account.storage_root == EMPTY_ROOT_HASH
                    && let Some((slot, _)) =
                        account.storage.iter().find(|(_, value)| !value.is_zero())
                {
                    return Err(WitnessStateError::StorageContradictsRoot {
                        address: *address,
                        slot: *slot,
                    });
                }
            }
        }
        let codes = codes
            .into_iter()
            .map(|code| (keccak256(&code), code))
            .collect();
        Ok(Self::assemble(
            vicinity,
            accounts,
            codes,
            ancestor_hashes,
            None,
            Coverage::Partial,
        ))
    }

    /// Builds a backend with lazy proofs against `pre_state_root`.
    /// Unprovable reads record [`WitnessDbError`]. Headers must be verified separately;
    /// `storage_keys` are unused because execution supplies addresses and slots.
    ///
    /// # Errors
    /// [`WitnessStateError::PreStateRootNotRevealed`] if a nonempty root node is missing.
    pub fn from_witness(
        vicinity: MemoryVicinity,
        witness: ExecutionWitness,
        pre_state_root: H256,
        ancestor_hashes: BTreeMap<u64, H256>,
    ) -> Result<Self, WitnessStateError> {
        let ExecutionWitness {
            state,
            contract_codes,
            ..
        } = witness;
        let nodes = NodeStore::new(state);
        if pre_state_root != EMPTY_ROOT_HASH && !nodes.contains(&pre_state_root.0) {
            return Err(WitnessStateError::PreStateRootNotRevealed { pre_state_root });
        }
        let codes = contract_codes
            .into_iter()
            .map(|code| (keccak256(&code), code))
            .collect();
        Ok(Self::assemble(
            vicinity,
            BTreeMap::new(),
            codes,
            ancestor_hashes,
            Some(RevealedTrie {
                nodes,
                state_root: pre_state_root,
            }),
            Coverage::Partial,
        ))
    }

    /// Builds a backend from complete state; unlisted accounts and slots are proven absent.
    #[must_use]
    pub fn from_full_state(
        vicinity: MemoryVicinity,
        state: BTreeMap<H160, MemoryAccount>,
        ancestor_hashes: BTreeMap<u64, H256>,
    ) -> Self {
        let mut codes = BTreeMap::new();
        let accounts = state
            .into_iter()
            .map(|(address, account)| {
                let code_hash = if account.code.is_empty() {
                    KECCAK_EMPTY
                } else {
                    let code_hash = keccak256(&account.code);
                    codes.insert(code_hash, account.code);
                    code_hash
                };
                let revealed = WitnessAccount {
                    nonce: account.nonce,
                    balance: account.balance,
                    code_hash,
                    storage_root: storage_root(&account.storage),
                    storage: account.storage,
                    storage_wiped: false,
                };
                (address, RevealedAccount::Present(revealed))
            })
            .collect();
        Self::assemble(
            vicinity,
            accounts,
            codes,
            ancestor_hashes,
            None,
            Coverage::Complete,
        )
    }

    const fn assemble(
        vicinity: MemoryVicinity,
        accounts: BTreeMap<H160, RevealedAccount>,
        codes: BTreeMap<H256, Vec<u8>>,
        ancestor_hashes: BTreeMap<u64, H256>,
        trie: Option<RevealedTrie>,
        coverage: Coverage,
    ) -> Self {
        Self {
            vicinity,
            accounts: RefCell::new(accounts),
            codes,
            ancestor_hashes,
            trie,
            coverage,
            missing: Cell::new(None),
            logs: Vec::new(),
        }
    }

    /// The first unproved read. Reject execution if this returns `Some`.
    #[must_use]
    pub const fn missing(&self) -> Option<WitnessDbError> {
        self.missing.get()
    }

    /// The accounts revealed so far, as execution has left them.
    #[must_use]
    pub fn accounts(&self) -> Ref<'_, BTreeMap<H160, RevealedAccount>> {
        self.accounts.borrow()
    }

    /// The code map, which execution extends with the code of every contract it creates.
    #[must_use]
    pub const fn codes(&self) -> &BTreeMap<H256, Vec<u8>> {
        &self.codes
    }

    /// Logs collected from every applied transaction, in order.
    #[must_use]
    pub fn logs(&self) -> &[Log] {
        &self.logs
    }

    /// The block environment reads are answered from.
    #[must_use]
    pub const fn vicinity(&self) -> &MemoryVicinity {
        &self.vicinity
    }

    /// The block environment, for the executor to set per-transaction fields.
    pub const fn vicinity_mut(&mut self) -> &mut MemoryVicinity {
        &mut self.vicinity
    }

    /// Applies post-block balance increments (EIP-4895 withdrawals) as the reference client's
    /// `increment_balances`: every recipient is touched, and a touched account left EIP-161 empty
    /// is removed once all increments are applied. Unrevealed recipients record a witness gap.
    pub fn increment_balances(&mut self, increments: impl IntoIterator<Item = (H160, U256)>) {
        let mut touched = Vec::new();
        for (address, amount) in increments {
            self.increment_balance(address, amount);
            touched.push(address);
        }
        let accounts = self.accounts.get_mut();
        for address in touched {
            if let Some(entry) = accounts.get_mut(&address)
                && matches!(entry, RevealedAccount::Present(account) if account.is_empty())
            {
                *entry = RevealedAccount::Absent;
            }
        }
    }

    /// Credits `amount`, creating a proven-absent account only for a nonzero amount.
    fn increment_balance(&mut self, address: H160, amount: U256) {
        self.ensure_resolved(address);
        let coverage = self.coverage;
        let missing = &self.missing;
        let entry = self.accounts.get_mut().entry(address).or_insert_with(|| {
            if coverage == Coverage::Partial && missing.get().is_none() {
                missing.set(Some(WitnessDbError::Account { address }));
            }
            RevealedAccount::Absent
        });
        match entry {
            RevealedAccount::Present(account) => {
                // Total supply is far below 2^256, so a real chain cannot overflow here.
                account.balance = account.balance.saturating_add(amount);
            }
            RevealedAccount::Absent => {
                if !amount.is_zero() {
                    // Created by the credit: a fresh account whose storage is provably empty.
                    *entry = RevealedAccount::Present(WitnessAccount {
                        balance: amount,
                        storage_wiped: true,
                        ..WitnessAccount::empty()
                    });
                }
            }
        }
    }

    /// Consumes the backend into its post-state, unless a read was unproven.
    ///
    /// # Errors
    /// The first recorded [`WitnessDbError`]; the state is discarded.
    pub fn try_into_state(self) -> Result<WitnessState, WitnessDbError> {
        match self.missing.get() {
            Some(missing) => Err(missing),
            None => Ok(WitnessState {
                accounts: self.accounts.into_inner(),
                codes: self.codes,
            }),
        }
    }

    /// Records the first unproved read without replacing it with subsequent failures.
    fn record_missing(&self, missing: WitnessDbError) {
        if self.missing.get().is_none() {
            self.missing.set(Some(missing));
        }
    }

    /// Reveals `address` from the trie if it has not been resolved yet.
    fn ensure_resolved(&self, address: H160) {
        let Some(trie) = &self.trie else {
            return;
        };
        if self.accounts.borrow().contains_key(&address) {
            return;
        }
        match trie.account(address) {
            Ok(revealed) => {
                self.accounts.borrow_mut().insert(address, revealed);
            }
            Err(missing) => self.record_missing(missing),
        }
    }

    /// Runs `read` on the account at `address`: `None` for a *proven-absent* one. Records
    /// [`WitnessDbError::Account`] and passes `None` when the witness said nothing.
    fn with_account<R>(&self, address: H160, read: impl FnOnce(Option<&WitnessAccount>) -> R) -> R {
        self.ensure_resolved(address);
        let accounts = self.accounts.borrow();
        match accounts.get(&address) {
            Some(RevealedAccount::Present(account)) => read(Some(account)),
            Some(RevealedAccount::Absent) => read(None),
            None => {
                // With a trie, a failed resolution has already been recorded; with a complete
                // state, absence is the proof.
                if self.coverage == Coverage::Partial && self.trie.is_none() {
                    self.record_missing(WitnessDbError::Account { address });
                }
                read(None)
            }
        }
    }

    /// Remembers a slot the trie resolved, so the next read and the post-state see it.
    fn cache_slot(&self, address: H160, slot: H256, value: H256) {
        if let Some(RevealedAccount::Present(account)) =
            self.accounts.borrow_mut().get_mut(&address)
        {
            account.storage.insert(slot, value);
        }
    }
}

impl Backend for WitnessBackend {
    #[allow(clippy::misnamed_getters)]
    fn gas_price(&self) -> U256 {
        self.vicinity.effective_gas_price
    }

    fn origin(&self) -> H160 {
        self.vicinity.origin
    }

    fn block_hash(&self, number: U256) -> H256 {
        let current = self.vicinity.block_number;
        // The current block and anything after it are not ancestors: zero by definition.
        if number >= current {
            return H256::zero();
        }
        // Outside the window `BLOCKHASH` is zero for every chain, so no proof is needed.
        if current - number > U256::from(BLOCKHASH_WINDOW) {
            return H256::zero();
        }
        let Ok(number) = u64::try_from(number) else {
            // Unreachable given the window check above; a number that far from `current` cannot be
            // within 256 of it. Zero is the same answer the range check would have given.
            return H256::zero();
        };
        self.ancestor_hashes.get(&number).map_or_else(
            || {
                self.record_missing(WitnessDbError::AncestorHash { number });
                H256::zero()
            },
            |hash| *hash,
        )
    }

    fn block_number(&self) -> U256 {
        self.vicinity.block_number
    }

    fn block_coinbase(&self) -> H160 {
        self.vicinity.block_coinbase
    }

    fn block_timestamp(&self) -> U256 {
        self.vicinity.block_timestamp
    }

    fn block_difficulty(&self) -> U256 {
        self.vicinity.block_difficulty
    }

    fn block_randomness(&self) -> Option<H256> {
        self.vicinity.block_randomness
    }

    fn block_gas_limit(&self) -> U256 {
        self.vicinity.block_gas_limit
    }

    fn block_base_fee_per_gas(&self) -> U256 {
        self.vicinity.block_base_fee_per_gas
    }

    fn chain_id(&self) -> U256 {
        self.vicinity.chain_id
    }

    fn exists(&self, address: H160) -> bool {
        // A proven-absent account does not exist; an unrevealed one poisons and reads as absent.
        self.with_account(address, |account| account.is_some())
    }

    fn basic(&self, address: H160) -> Basic {
        self.with_account(address, |account| {
            account.map_or_else(Basic::default, |account| Basic {
                balance: account.balance,
                nonce: account.nonce,
            })
        })
    }

    fn code(&self, address: H160) -> Vec<u8> {
        // Proven to have no code by its leaf, so the empty answer needs no bytes.
        let code_hash = self.with_account(address, |account| {
            account
                .filter(|account| account.has_code())
                .map(|account| account.code_hash)
        });
        let Some(code_hash) = code_hash else {
            return Vec::new();
        };
        self.codes.get(&code_hash).map_or_else(
            || {
                // The set-mismatch case this module exists for: touched account, code never loaded.
                self.record_missing(WitnessDbError::Code { address, code_hash });
                Vec::new()
            },
            Clone::clone,
        )
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        let pending = self.with_account(address, |account| {
            let Some(account) = account else {
                return Slot::Zero;
            };
            if let Some(value) = account.storage.get(&index) {
                return Slot::Value(*value);
            }
            if account.unlisted_slots_are_zero() {
                return Slot::Zero;
            }
            Slot::Unresolved(account.storage_root)
        });
        let storage_root = match pending {
            Slot::Value(value) => return value,
            Slot::Zero => return H256::zero(),
            Slot::Unresolved(storage_root) => storage_root,
        };
        // Nothing revealed for this slot under a non-empty root: a complete state proves it zero,
        // a trie may still prove it, and otherwise the witness owed a proof it did not supply.
        match (self.coverage, &self.trie) {
            (Coverage::Complete, _) => H256::zero(),
            (Coverage::Partial, None) => {
                self.record_missing(WitnessDbError::StorageSlot {
                    address,
                    slot: index,
                });
                H256::zero()
            }
            (Coverage::Partial, Some(trie)) => match trie.slot(address, storage_root, index) {
                Ok(value) => {
                    self.cache_slot(address, index, value);
                    value
                }
                Err(missing) => {
                    self.record_missing(missing);
                    H256::zero()
                }
            },
        }
    }

    fn is_empty_storage(&self, address: H160) -> bool {
        // Answered from the leaf's `storage_root` plus the wipe flag, so a revealed account needs no
        // slot revealed to answer it. That matters because EIP-7610 asks this about the account a
        // create is colliding with, whose storage a witness has no reason to enumerate. The account
        // itself must still be revealed — an unrevealed one poisons through `with_account`, since
        // nothing is known about its storage either.
        self.with_account(address, |account| {
            account.is_none_or(WitnessAccount::is_storage_empty)
        })
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        Some(self.storage(address, index))
    }

    fn blob_gas_price(&self) -> Option<u128> {
        self.vicinity.blob_gas_price
    }

    fn get_blob_hash(&self, index: usize) -> Option<U256> {
        self.vicinity.blob_hashes.get(index).copied()
    }
}

impl ApplyBackend for WitnessBackend {
    fn apply<A, I, L>(&mut self, values: A, logs: L, delete_empty: bool)
    where
        A: IntoIterator<Item = Apply<I>>,
        I: IntoIterator<Item = (H256, H256)>,
        L: IntoIterator<Item = Log>,
    {
        for apply in values {
            match apply {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage,
                } => {
                    // Execution reads an account before it modifies it, so a trie-backed account
                    // is normally resolved by now; this covers writes that skipped the read.
                    self.ensure_resolved(address);
                    let coverage = self.coverage;
                    let missing = &self.missing;
                    let entry = self.accounts.get_mut().entry(address).or_insert_with(|| {
                        // Writing to an account the witness never revealed is itself unproven:
                        // the pre-state it is being modified *from* is unknown.
                        if coverage == Coverage::Partial && missing.get().is_none() {
                            missing.set(Some(WitnessDbError::Account { address }));
                        }
                        RevealedAccount::Present(WitnessAccount::empty())
                    });
                    // An account deleted by an *earlier* transaction can be touched again by a
                    // later one, so absence is not final. Not a same-batch case: `deconstruct`
                    // skips deleted addresses in its `Modify` loop and appends every `Delete`
                    // after it (`executor/stack/memory.rs:91-93,128-130`), so within one batch a
                    // `Delete` never precedes a `Modify` for the same address.
                    if matches!(entry, RevealedAccount::Absent) {
                        // `storage_wiped`, not just the empty `storage_root` that
                        // `WitnessAccount::empty` supplies: deletion destroyed the storage, and the
                        // two fields are one encoding that must agree (see `storage_root`).
                        *entry = RevealedAccount::Present(WitnessAccount {
                            storage_wiped: true,
                            ..WitnessAccount::empty()
                        });
                    }
                    let RevealedAccount::Present(account) = entry else {
                        unreachable!("just replaced any Absent entry with a Present one");
                    };

                    account.balance = basic.balance;
                    account.nonce = basic.nonce;
                    if let Some(code) = code {
                        // Register the bytes under their own hash and point the leaf at it, so a
                        // contract created in this block is readable by the very next transaction.
                        let code_hash = keccak256(&code);
                        account.code_hash = code_hash;
                        self.codes.entry(code_hash).or_insert(code);
                    }
                    if reset_storage {
                        account.storage = BTreeMap::new();
                        // Preserved, unlike the full-state backend which drops it: after a wipe an
                        // unlisted slot is provably zero, and without the flag it would be
                        // indistinguishable from one the witness omitted.
                        account.storage_wiped = true;
                    }
                    // Zeros are kept rather than pruned — see `WitnessAccount::storage`.
                    for (index, value) in storage {
                        account.storage.insert(index, value);
                    }

                    // EIP-161 `EMPTY(σ,a)` is nonce, balance and code hash — storage is **not**
                    // part of it, and adding it here would keep an account the protocol prunes,
                    // leaving a leaf in the post-state that no state root expects. The same
                    // predicate, storage-free, is what the full-state backend uses
                    // (`backend/memory.rs:237-239`) and what this crate's own
                    // `trie::is_empty_account` uses.
                    if delete_empty && account.is_empty() {
                        // Such an account is not part of the state trie. Recorded as *proven*
                        // absent, because that is what execution just established.
                        self.accounts
                            .get_mut()
                            .insert(address, RevealedAccount::Absent);
                    }
                }
                Apply::Delete { address } => {
                    self.accounts
                        .get_mut()
                        .insert(address, RevealedAccount::Absent);
                }
            }
        }

        self.logs.extend(logs);
    }
}

/// Invalid initial witness state; execution-time proof gaps use [`WitnessDbError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessStateError {
    /// An account's storage root says its storage is empty, yet a non-zero slot was revealed for it.
    StorageContradictsRoot {
        /// The account.
        address: H160,
        /// The first non-zero slot found under an empty storage root.
        slot: H256,
    },
    /// No revealed node hashes to the pre-state root, so nothing can be proven against it.
    PreStateRootNotRevealed {
        /// The parent's state root.
        pre_state_root: H256,
    },
}

impl fmt::Display for WitnessStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageContradictsRoot { address, slot } => write!(
                f,
                "account {address:?} has an empty storage root but a non-zero slot {slot:?}"
            ),
            Self::PreStateRootNotRevealed { pre_state_root } => {
                write!(
                    f,
                    "witness reveals no node for pre-state root {pre_state_root:?}"
                )
            }
        }
    }
}

impl core::error::Error for WitnessStateError {}

/// A missing or malformed proof, code entry, or ancestor required by execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessDbError {
    /// The witness revealed nothing about this address — neither its fields nor its absence.
    Account {
        /// The address that was read.
        address: H160,
    },
    /// The account has code, but no supplied bytes match its `code_hash`.
    Code {
        /// The account whose code was read.
        address: H160,
        /// The code hash from the account's trie leaf, which no supplied code matches.
        code_hash: H256,
    },
    /// The account is known, its storage is not empty, and this slot was neither revealed nor
    /// proven absent.
    StorageSlot {
        /// The account whose storage was read.
        address: H160,
        /// The slot that was read.
        slot: H256,
    },
    /// `BLOCKHASH` reached inside the 256-block window, but no ancestor hash was supplied for it.
    AncestorHash {
        /// The block number that was read.
        number: u64,
    },
    /// A trie node a read needed was not revealed, or is not a valid node.
    TrieNode {
        /// The hash the node's parent refers to it by.
        hash: H256,
    },
    /// A revealed leaf of this account — its own or one of its storage slots — does not decode.
    Leaf {
        /// The account the leaf belongs to.
        address: H160,
    },
}

impl fmt::Display for WitnessDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Account { address } => {
                write!(f, "witness revealed nothing about account {address:?}")
            }
            Self::Code { address, code_hash } => write!(
                f,
                "witness omitted the code of account {address:?} (code_hash {code_hash:?})"
            ),
            Self::StorageSlot { address, slot } => write!(
                f,
                "witness omitted storage slot {slot:?} of account {address:?}"
            ),
            Self::AncestorHash { number } => {
                write!(f, "witness omitted the header of ancestor block {number}")
            }
            Self::TrieNode { hash } => {
                write!(f, "witness omitted or corrupted trie node {hash:?}")
            }
            Self::Leaf { address } => {
                write!(f, "witness leaf of account {address:?} does not decode")
            }
        }
    }
}

impl core::error::Error for WitnessDbError {}
