//! Production integration: commitment failures, root reconstruction and error boundaries.

use super::{cancun_child, cancun_parent, chain_spec};
use crate::block::{Block, Header};
use crate::bloom::Bloom;
use crate::chain_spec::ChainSpec;
use crate::constants::{EMPTY_REQUESTS_HASH, EMPTY_ROOT_HASH};
use crate::crypto::keccak256;
use crate::errors::BlockExecutionError;
use crate::execution_types::execution::{BlockExecutionOutput, BlockExecutionResult};
use crate::execution_types::witness::ExecutionWitness;
use crate::requests::Requests;
use crate::spec::Spec;
use crate::stateless::{StatelessValidationError, stateless_validation, validate_execution_output};
use crate::system_calls::{
    BEACON_ROOTS_ADDRESS, CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
    WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
};
use crate::test_utils::witness_of;
use crate::trie::{StateRootError, TrieAccount, ordered_trie_root, state_root};
use crate::withdrawal::Withdrawal;
use crate::witness_backend::{WitnessDbError, WitnessState};
use aurora_evm::backend::MemoryAccount;
use aurora_evm_trie::sparse::{LookupError, PatchError};
use core::error::Error;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

fn empty_block(spec: Spec) -> (Block, ExecutionWitness, ChainSpec) {
    let mut chain = chain_spec();
    chain.spec = spec;
    if spec >= Spec::Prague {
        chain.hard_forks_timestamps.insert(Spec::Prague, 0);
    }
    if spec >= Spec::Osaka {
        chain.hard_forks_timestamps.insert(Spec::Osaka, 0);
    }
    let mut pre = BTreeMap::new();
    if spec >= Spec::Prague {
        // Nonempty STOP runtimes return no requests and leave their pre-state unchanged.
        for address in [
            WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
        ] {
            pre.insert(
                address,
                MemoryAccount {
                    code: vec![0x00],
                    ..MemoryAccount::default()
                },
            );
        }
    }
    let (root, mut witness) = witness_of(&pre);
    let mut parent = cancun_parent(root);
    parent.requests_hash = (spec >= Spec::Prague).then_some(EMPTY_REQUESTS_HASH);
    witness.headers.push(rlp::encode(&parent).to_vec());
    let mut block = cancun_child(&parent, H256::zero());
    block.header.state_root = root;
    block.header.requests_hash = parent.requests_hash;
    (block, witness, chain)
}

#[test]
fn public_entry_point_accepts_matching_commitments_on_all_supported_forks() {
    for spec in [Spec::Cancun, Spec::Prague, Spec::Osaka] {
        let (block, witness, chain) = empty_block(spec);
        let expected_hash = block.header.hash_slow();
        let output = stateless_validation(block, &[], witness, chain).unwrap();
        assert_eq!(output.block_hash, expected_hash);
        assert_eq!(output.execution_output.result.gas_used, 0);
        assert_eq!(output.execution_output.result.receipts, []);
    }
}

#[test]
fn public_entry_point_rejects_each_post_execution_header_mismatch() {
    let (block, witness, chain) = empty_block(Spec::Prague);
    let wrong = H256::repeat_byte(0xab);
    for field in 0..5 {
        let mut changed = block.clone();
        let error = match field {
            0 => {
                changed.header.gas_used = 1;
                BlockExecutionError::GasUsedMismatch {
                    got: 0,
                    expected: 1,
                }
            }
            1 => {
                changed.header.receipts_root = wrong;
                BlockExecutionError::ReceiptsRootMismatch {
                    got: EMPTY_ROOT_HASH,
                    expected: wrong,
                }
            }
            2 => {
                changed.header.logs_bloom.0[17] = 1;
                BlockExecutionError::LogsBloomMismatch {
                    got: Box::new(Bloom::zero()),
                    expected: Box::new(changed.header.logs_bloom.clone()),
                }
            }
            3 => {
                changed.header.requests_hash = Some(wrong);
                BlockExecutionError::RequestsHashMismatch {
                    got: Some(EMPTY_REQUESTS_HASH),
                    expected: Some(wrong),
                }
            }
            4 => {
                changed.header.state_root = wrong;
                BlockExecutionError::StateRootMismatch {
                    got: block.header.state_root,
                    expected: wrong,
                }
            }
            _ => unreachable!(),
        };
        assert_eq!(
            stateless_validation(changed, &[], witness.clone(), chain.clone()),
            Err(StatelessValidationError::PostExecution(error))
        );
    }
}

#[test]
fn every_execution_commitment_is_checked_before_sparse_root_reconstruction() {
    let (block, _, chain) = empty_block(Spec::Prague);
    let active = chain.active_spec_at_timestamp(block.timestamp).unwrap();
    // Deliberately no trie: reaching reconstruction must return NoTrie, never succeed.
    let output = BlockExecutionOutput {
        result: BlockExecutionResult {
            receipts: vec![],
            requests: Requests::new(),
            gas_used: 0,
            blob_gas_used: 0,
        },
        state: WitnessState {
            accounts: BTreeMap::new(),
            codes: BTreeMap::new(),
            trie: None,
            changes: BTreeMap::new(),
        },
    };
    let wrong = H256::repeat_byte(1);
    let cases = [
        (
            Header {
                gas_used: 1,
                ..block.header.clone()
            },
            BlockExecutionError::GasUsedMismatch {
                got: 0,
                expected: 1,
            },
        ),
        (
            Header {
                blob_gas_used: None,
                ..block.header.clone()
            },
            BlockExecutionError::BlobGasUsedMismatch {
                got: 0,
                expected: None,
            },
        ),
        (
            Header {
                receipts_root: wrong,
                ..block.header.clone()
            },
            BlockExecutionError::ReceiptsRootMismatch {
                got: EMPTY_ROOT_HASH,
                expected: wrong,
            },
        ),
        (
            Header {
                logs_bloom: Bloom([1; 256]),
                ..block.header.clone()
            },
            BlockExecutionError::LogsBloomMismatch {
                got: Box::new(Bloom::zero()),
                expected: Box::new(Bloom([1; 256])),
            },
        ),
        (
            Header {
                requests_hash: None,
                ..block.header.clone()
            },
            BlockExecutionError::RequestsHashMismatch {
                got: Some(EMPTY_REQUESTS_HASH),
                expected: None,
            },
        ),
    ];
    for (header, error) in cases {
        assert_eq!(
            validate_execution_output(&header, &active, &output),
            Err(StatelessValidationError::PostExecution(error))
        );
    }
    assert_eq!(
        validate_execution_output(&block.header, &active, &output),
        Err(StatelessValidationError::StateRoot(StateRootError::NoTrie))
    );
}

#[test]
fn root_errors_preserve_node_identity_and_separate_internal_invariants() {
    let hash = H256::repeat_byte(0x42);
    for (node, expected) in [
        (
            LookupError::BlindedNode(hash.0),
            WitnessDbError::BlindedNode { hash },
        ),
        (
            LookupError::MalformedNode(hash.0),
            WitnessDbError::MalformedNode { hash },
        ),
    ] {
        assert_eq!(
            StatelessValidationError::from(StateRootError::Patch(PatchError::Node(node))),
            StatelessValidationError::Execution(BlockExecutionError::MissingWitness(expected))
        );
    }
    for error in [
        StateRootError::NoTrie,
        StateRootError::MissingAccount(H160::repeat_byte(1)),
        StateRootError::MissingStorageSlot {
            address: H160::repeat_byte(2),
            slot: hash,
        },
        StateRootError::Patch(PatchError::EmptyValue),
    ] {
        let mapped = StatelessValidationError::from(error);
        assert_eq!(mapped, StatelessValidationError::StateRoot(error));
        assert_eq!(mapped.to_string(), "state root reconstruction failed");
        assert_eq!(
            mapped.source().unwrap().downcast_ref::<StateRootError>(),
            Some(&error)
        );
    }
    let cause = BlockExecutionError::StateRootMismatch {
        got: hash,
        expected: EMPTY_ROOT_HASH,
    };
    let error = StatelessValidationError::PostExecution(cause.clone());
    assert_eq!(error.to_string(), "post-execution validation failed");
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<BlockExecutionError>(),
        Some(&cause)
    );
}

/// A zero withdrawal prunes an empty account; collapsing the trie then needs its untouched sibling.
#[test]
fn missing_collapse_sibling_fails_after_execution_in_the_public_path() {
    let beacon_nibble = keccak256(BEACON_ROOTS_ADDRESS.as_bytes()).0[0] >> 4;
    let recipient = (1..100)
        .map(H160::from_low_u64_be)
        .find(|address| keccak256(address.as_bytes()).0[0] >> 4 != beacon_nibble)
        .unwrap();
    let recipient_nibble = keccak256(recipient.as_bytes()).0[0] >> 4;
    let sibling = (1..100)
        .map(H160::from_low_u64_be)
        .find(|address| {
            let nibble = keccak256(address.as_bytes()).0[0] >> 4;
            nibble != beacon_nibble && nibble != recipient_nibble
        })
        .unwrap();
    let mut pre = BTreeMap::from([
        (recipient, MemoryAccount::default()),
        (
            sibling,
            MemoryAccount {
                balance: U256::one(),
                ..MemoryAccount::default()
            },
        ),
    ]);
    let (root, mut witness) = witness_of(&pre);
    let parent = cancun_parent(root);
    witness.headers.push(rlp::encode(&parent).to_vec());
    let mut block = cancun_child(&parent, H256::zero());
    let withdrawal = Withdrawal {
        index: 0,
        validator_index: 0,
        address: recipient,
        amount: 0,
    };
    block.header.withdrawals_root = Some(ordered_trie_root([rlp::encode(&withdrawal)]));
    block.body.withdrawals = Some(vec![withdrawal]);
    pre.remove(&recipient);
    block.header.state_root = state_root(&pre);
    assert!(stateless_validation(block.clone(), &[], witness.clone(), chain_spec()).is_ok());

    let index = witness
        .state
        .iter()
        .position(|node| {
            rlp::Rlp::new(node).val_at::<Vec<u8>>(1).is_ok_and(|value| {
                rlp::decode::<TrieAccount>(&value)
                    .is_ok_and(|account| account.balance == U256::one())
            })
        })
        .unwrap();
    let hash = keccak256(&witness.state.remove(index));
    let expected = StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
        WitnessDbError::BlindedNode { hash },
    ));
    assert_eq!(
        stateless_validation(block.clone(), &[], witness.clone(), chain_spec()),
        Err(expected)
    );

    // A receipt mismatch must win even when reconstruction would need the withheld sibling.
    block.header.receipts_root = H256::zero();
    assert_eq!(
        stateless_validation(block, &[], witness, chain_spec()),
        Err(StatelessValidationError::PostExecution(
            BlockExecutionError::ReceiptsRootMismatch {
                got: EMPTY_ROOT_HASH,
                expected: H256::zero()
            }
        ))
    );
}
