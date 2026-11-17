//! A signed transaction through [`stateless_validation`] whose `SSTORE` halts under the EIP-2200
//! stipend: the reference client never loads the slot, so its witness omits it.

use super::{cancun_child, cancun_parent, chain_spec, sender_key, signed_call};
use crate::block::{Block, UncompressedPublicKey};
use crate::crypto::{address_from_uncompressed_public_key, keccak256};
use crate::errors::BlockExecutionError;
use crate::execution_types::witness::ExecutionWitness;
use crate::receipt::Receipt;
use crate::stateless::{StatelessValidationError, stateless_validation};
use crate::test_utils::witness_of;
use crate::transaction::TxType;
use crate::trie::{ordered_trie_root, receipts_root, state_root};
use crate::witness_backend::{RevealedAccount, WitnessDbError};
use aurora_evm::backend::MemoryAccount;
use aurora_evm_trie::sparse::reference::hashed_nodes;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

const CONTRACT: H160 = H160::repeat_byte(0xc1);
/// `SSTORE(0, 1), STOP`: 6 gas of pushes before the store.
const SSTORE_ONE: [u8; 6] = [0x60, 1, 0x60, 0, 0x55, 0x00];
/// Leaves exactly the 2 300 gas stipend at the store.
const STIPEND_GAS_LIMIT: u64 = 21_000 + 6 + 2_300;
/// One above the block's base fee, so the coinbase is paid.
const GAS_PRICE: u64 = 2;

/// A Cancun block of one call to `CONTRACT`, which owns slot 0, proven by a witness that
/// withholds that slot's node. The header commits to the call burning its whole `gas_limit`.
/// Returns the block, the witness, the sender's key and the withheld node's hash.
fn block_calling_contract(
    gas_limit: u64,
) -> (Block, ExecutionWitness, UncompressedPublicKey, H256) {
    let (secret, public_key) = sender_key();
    let caller = address_from_uncompressed_public_key(&public_key.0);
    let pre = BTreeMap::from([
        (
            caller,
            MemoryAccount {
                balance: U256::from(1_000_000u64),
                ..MemoryAccount::default()
            },
        ),
        (
            CONTRACT,
            MemoryAccount {
                nonce: U256::one(),
                storage: BTreeMap::from([(H256::zero(), H256::from_low_u64_be(1))]),
                code: SSTORE_ONE.to_vec(),
                ..MemoryAccount::default()
            },
        ),
    ]);
    let (root, mut witness) = witness_of(&pre);
    // The contract's storage trie is its one leaf: withhold it.
    let (storage_root, _) = hashed_nodes(&BTreeMap::from([(
        keccak256(H256::zero().as_bytes()).as_bytes().to_vec(),
        rlp::encode(&U256::one()).to_vec(),
    )]));
    witness
        .state
        .retain(|node| keccak256(node).0 != storage_root);
    let parent = cancun_parent(root);
    witness.headers = vec![rlp::encode(&parent).to_vec()];
    let tx = signed_call(&secret, CONTRACT, gas_limit);
    // The sender pays `gas_limit` at `GAS_PRICE`; the coinbase keeps what is above the base fee.
    let mut post = pre;
    let sender = post.get_mut(&caller).unwrap();
    sender.nonce = U256::one();
    sender.balance -= U256::from(GAS_PRICE * gas_limit);
    post.insert(
        H160::zero(),
        MemoryAccount {
            balance: U256::from((GAS_PRICE - 1) * gas_limit),
            ..MemoryAccount::default()
        },
    );
    let mut block = cancun_child(&parent, H256::zero());
    block.header.gas_used = gas_limit;
    block.header.transactions_root = ordered_trie_root([tx.encoded_2718()]);
    block.header.receipts_root =
        receipts_root(&[Receipt::new(TxType::Legacy, false, gas_limit, Vec::new())]);
    block.header.state_root = state_root(&post);
    block.body.transactions = vec![tx];
    (block, witness, public_key, H256(storage_root))
}

#[test]
fn an_sstore_under_the_stipend_validates_without_its_slot() {
    let (block, witness, public_key, _) = block_calling_contract(STIPEND_GAS_LIMIT);
    let expected_hash = block.header.hash_slow();

    let output = stateless_validation(block, &[public_key], witness, chain_spec()).unwrap();

    assert_eq!(output.block_hash, expected_hash);
    assert_eq!(output.execution_output.result.gas_used, STIPEND_GAS_LIMIT);
    assert!(!output.execution_output.result.receipts[0].success);
    let RevealedAccount::Present(contract) = &output.execution_output.state.accounts[&CONTRACT]
    else {
        panic!("the contract was revealed");
    };
    assert!(
        contract.storage.is_empty(),
        "the slot was neither read nor written"
    );
}

/// One gas above the sentry, SSTORE must read its slot even if its full cost is unaffordable.
#[test]
fn an_sstore_one_gas_above_the_stipend_still_needs_its_slot() {
    let (block, witness, public_key, withheld) = block_calling_contract(STIPEND_GAS_LIMIT + 1);

    let error = stateless_validation(block, &[public_key], witness, chain_spec()).unwrap_err();

    match error {
        StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
            WitnessDbError::BlindedNode { hash },
        )) => assert_eq!(hash, withheld),
        other => panic!("unexpected {other:?}"),
    }
}
