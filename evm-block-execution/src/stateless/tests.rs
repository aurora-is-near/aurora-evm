mod eest;

use super::{StatelessValidationError, stateless_validation};
use crate::block::{
    AncestorChainError, Block, BlockBody, BlockRecoveryError, BlockValidationError, Header,
};
use crate::chain_spec::ChainSpec;
use crate::eips::eip1559::BaseFeeParams;
use crate::eips::eip7892::BlobScheduleBlobParams;
use crate::errors::BlockExecutionError;
use crate::execution_types::witness::ExecutionWitness;
use crate::spec::Spec;
use crate::system_calls::BEACON_ROOTS_ADDRESS;
use crate::test_support::witness_of;
use crate::witness_backend::{RevealedAccount, WitnessDbError, WitnessStateError};
use aurora_evm::backend::MemoryAccount;
use hex_literal::hex;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

/// Mainnet runtime code of the EIP-4788 beacon-roots contract.
const EIP4788_CODE: &[u8] = &hex!(
    "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff"
    "810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff0155"
    "00"
);

fn chain_spec() -> ChainSpec {
    ChainSpec {
        chain_id: 1,
        spec: Spec::Cancun,
        hard_forks_timestamps: BTreeMap::from([(Spec::Cancun, 0)]),
        deposit_contract_address: None,
        base_fee_params: BaseFeeParams::ethereum(),
        blob_schedule: BlobScheduleBlobParams::mainnet(),
    }
}

#[test]
fn every_stage_keeps_details_only_in_its_source() {
    use crate::block::SenderRecoveryError;
    use core::error::Error;

    let cases = [
        (
            StatelessValidationError::AncestorChain(AncestorChainError::MissingParent),
            "ancestor chain is invalid",
            "the block's parent header is missing",
        ),
        (
            StatelessValidationError::Consensus(BlockValidationError::CancunNotActive {
                timestamp: 17,
            }),
            "block consensus validation failed",
            "Cancun is not active at timestamp 17",
        ),
        (
            StatelessValidationError::SenderRecovery(SenderRecoveryError::InvalidPublicKey {
                index: 17,
            }),
            "sender recovery failed",
            "public key for transaction 17 is not a valid point",
        ),
        (
            StatelessValidationError::Recovery(BlockRecoveryError::SenderCountMismatch {
                senders: 1,
                transactions: 2,
            }),
            "block recovery is inconsistent",
            "block has 2 transactions but 1 senders were supplied",
        ),
        (
            StatelessValidationError::Witness(WitnessStateError::PreStateRootNotRevealed {
                pre_state_root: H256::zero(),
            }),
            "witness cannot be used",
            "witness reveals no node for pre-state root 0x0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            StatelessValidationError::Execution(BlockExecutionError::SenderHasCode),
            "block execution failed",
            "sender has non-delegation code (EIP-3607)",
        ),
    ];
    for (error, context, details) in cases {
        assert_eq!(error.to_string(), context);
        let source = error.source().unwrap();
        assert_eq!(source.to_string(), details);
        assert!(source.source().is_none());
    }
}

#[test]
fn a_missing_ancestor_fails_before_execution() {
    let error = stateless_validation(
        Block::default(),
        &[],
        ExecutionWitness::default(),
        chain_spec(),
    )
    .unwrap_err();

    assert_eq!(
        error,
        StatelessValidationError::AncestorChain(AncestorChainError::MissingParent)
    );
}

#[test]
fn consensus_validation_runs_before_execution() {
    let mut parent = Header {
        number: 1,
        timestamp: 1,
        ..Header::default()
    };
    parent.base_fee_per_gas = Some(1);
    parent.withdrawals_root = Some(crate::constants::EMPTY_ROOT_HASH);
    parent.blob_gas_used = Some(0);
    parent.excess_blob_gas = Some(0);
    parent.parent_beacon_block_root = Some(H256::default());

    let block = Block::new(
        Header {
            parent_hash: parent.hash_slow(),
            number: 2,
            timestamp: 2,
            difficulty: U256::one(),
            ..Header::default()
        },
        BlockBody::default(),
    );
    let witness = ExecutionWitness {
        headers: vec![rlp::encode(&parent).to_vec()],
        ..ExecutionWitness::default()
    };

    assert!(matches!(
        stateless_validation(block, &[], witness, chain_spec()),
        Err(StatelessValidationError::Consensus(
            BlockValidationError::DifficultyNotZero { .. }
        ))
    ));
}

/// A parent header whose fields satisfy every Cancun rule the child is checked against.
fn cancun_parent(state_root: H256) -> Header {
    Header {
        number: 1,
        timestamp: 1,
        gas_limit: 30_000_000,
        state_root,
        base_fee_per_gas: Some(1),
        withdrawals_root: Some(crate::constants::EMPTY_ROOT_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(H256::zero()),
        ..Header::default()
    }
}

/// An empty Cancun block on top of `parent`.
fn cancun_child(parent: &Header, beacon_root: H256) -> Block {
    Block::new(
        Header {
            parent_hash: parent.hash_slow(),
            number: 2,
            timestamp: 20_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1),
            withdrawals_root: Some(crate::constants::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(beacon_root),
            ..Header::default()
        },
        BlockBody::new(Vec::new(), Some(Vec::new())),
    )
}

/// The pre-state: the EIP-4788 contract and an unrelated holder, so the state trie branches.
fn beacon_root_state() -> BTreeMap<H160, MemoryAccount> {
    let mut state = BTreeMap::new();
    state.insert(
        BEACON_ROOTS_ADDRESS,
        MemoryAccount {
            nonce: U256::one(),
            balance: U256::zero(),
            storage: BTreeMap::new(),
            code: EIP4788_CODE.to_vec(),
        },
    );
    state.insert(
        H160::repeat_byte(0xaa),
        MemoryAccount {
            nonce: U256::zero(),
            balance: U256::from(5u64),
            storage: BTreeMap::new(),
            code: Vec::new(),
        },
    );
    state
}

#[test]
fn an_empty_block_is_validated_and_executed_against_its_witness() {
    let state = beacon_root_state();
    let (state_root, mut witness) = witness_of(&state);
    let parent = cancun_parent(state_root);
    witness.headers = vec![rlp::encode(&parent).to_vec()];
    let beacon_root = H256::repeat_byte(0xbe);
    let block = cancun_child(&parent, beacon_root);
    let expected_hash = block.header.hash_slow();

    let output = stateless_validation(block, &[], witness, chain_spec()).unwrap();

    assert_eq!(output.block_hash, expected_hash);
    assert_eq!(output.execution_output.result.gas_used, 0);
    assert!(output.execution_output.result.receipts.is_empty());
    assert!(output.execution_output.result.requests.is_empty());
    // The EIP-4788 system call ran against state proven by the witness.
    let RevealedAccount::Present(contract) =
        &output.execution_output.state.accounts[&BEACON_ROOTS_ADDRESS]
    else {
        panic!("the contract was revealed");
    };
    assert_eq!(
        contract.storage[&H256::from_low_u64_be(20_000 % 8191 + 8191)],
        beacon_root
    );
    // Untouched accounts are never revealed.
    assert!(
        !output
            .execution_output
            .state
            .accounts
            .contains_key(&H160::repeat_byte(0xaa))
    );
}

#[test]
fn a_witness_missing_a_touched_leaf_fails_the_block() {
    let state = beacon_root_state();
    let (state_root, mut witness) = witness_of(&state);
    let parent = cancun_parent(state_root);
    witness.headers = vec![rlp::encode(&parent).to_vec()];
    // Withhold the contract's account leaf: the branch root stays, so the witness still binds.
    let contract_code_hash = crate::crypto::keccak256(EIP4788_CODE);
    let leaf = witness
        .state
        .iter()
        .position(|node| {
            let node = rlp::Rlp::new(node);
            node.item_count() == Ok(2)
                && node.val_at::<Vec<u8>>(1).is_ok_and(|value| {
                    rlp::decode::<crate::trie::TrieAccount>(&value)
                        .is_ok_and(|account| account.code_hash == contract_code_hash)
                })
        })
        .expect("the contract's account leaf is a hashed node");
    let withheld = crate::crypto::keccak256(&witness.state.remove(leaf));
    let block = cancun_child(&parent, H256::repeat_byte(0xbe));

    let error = stateless_validation(block, &[], witness, chain_spec()).unwrap_err();
    match error {
        StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
            WitnessDbError::TrieNode { hash },
        )) => assert_eq!(hash, withheld),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn a_witness_without_the_pre_state_root_is_rejected_before_execution() {
    let state = beacon_root_state();
    let (state_root, mut witness) = witness_of(&state);
    let parent = cancun_parent(state_root);
    witness.headers = vec![rlp::encode(&parent).to_vec()];
    witness.state.clear();
    let block = cancun_child(&parent, H256::repeat_byte(0xbe));
    assert_eq!(
        stateless_validation(block, &[], witness, chain_spec()).unwrap_err(),
        StatelessValidationError::Witness(WitnessStateError::PreStateRootNotRevealed {
            pre_state_root: state_root
        })
    );
}
