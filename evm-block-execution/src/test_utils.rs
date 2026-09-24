//! Shared test helpers: witnesses derived from a known full state.

use crate::constants::KECCAK_EMPTY;
use crate::crypto::keccak256;
use crate::execution_types::witness::ExecutionWitness;
use crate::trie::TrieAccount;
use aurora_evm::backend::MemoryAccount;
use aurora_evm_trie::sparse::reference::hashed_nodes;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

/// Every hashed node of the state and storage tries over `accounts`, plus every code, as a
/// witness would list them — a superset of what any block over this state needs. Returns the
/// state root the witness proves.
pub fn witness_of(accounts: &BTreeMap<H160, MemoryAccount>) -> (H256, ExecutionWitness) {
    let mut nodes = Vec::new();
    let mut codes = Vec::new();
    let mut leaves = BTreeMap::new();
    for (address, account) in accounts {
        let slots: BTreeMap<Vec<u8>, Vec<u8>> = account
            .storage
            .iter()
            .filter(|(_, value)| !value.is_zero())
            .map(|(key, value)| {
                (
                    keccak256(key.as_bytes()).as_bytes().to_vec(),
                    rlp::encode(&U256::from_big_endian(value.as_bytes())).to_vec(),
                )
            })
            .collect();
        let (storage_root, storage_nodes) = hashed_nodes(&slots);
        nodes.extend(storage_nodes);
        let code_hash = if account.code.is_empty() {
            KECCAK_EMPTY
        } else {
            codes.push(account.code.clone());
            keccak256(&account.code)
        };
        let leaf = TrieAccount {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: H256(storage_root),
            code_hash,
            code_version: U256::zero(),
        };
        leaves.insert(
            keccak256(address.as_bytes()).as_bytes().to_vec(),
            rlp::encode(&leaf).to_vec(),
        );
    }
    let (root, state_nodes) = hashed_nodes(&leaves);
    nodes.extend(state_nodes);
    (
        H256(root),
        ExecutionWitness {
            state: nodes,
            contract_codes: codes,
            storage_keys: Vec::new(),
            headers: Vec::new(),
        },
    )
}
