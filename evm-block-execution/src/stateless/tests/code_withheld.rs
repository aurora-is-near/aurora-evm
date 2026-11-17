//! Signed blocks with bytecode omitted from hash-only paths, through the public validator.

use super::{cancun_child, cancun_parent, chain_spec, sender_key, signed_call};
use crate::block::{Block, UncompressedPublicKey};
use crate::chain_spec::ChainSpec;
use crate::constants::EMPTY_REQUESTS_HASH;
use crate::crypto::{address_from_uncompressed_public_key, keccak256};
use crate::errors::BlockExecutionError;
use crate::execution_types::witness::ExecutionWitness;
use crate::receipt::Receipt;
use crate::spec::Spec;
use crate::stateless::{StatelessValidationError, stateless_validation};
use crate::system_calls::{
    CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS, WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
};
use crate::test_utils::witness_of;
use crate::transaction::TxType;
use crate::trie::{ordered_trie_root, receipts_root, state_root, witness_state_root};
use crate::withdrawal::Withdrawal;
use crate::witness_backend::WitnessDbError;
use aurora_evm::backend::MemoryAccount;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

const PROBER: H160 = H160::repeat_byte(0xc1);
const TARGET: H160 = H160::repeat_byte(0xc2);
const TARGET_CODE: &[u8] = &[0x60, 1, 0x00];
const FORKS: [Spec; 3] = [Spec::Cancun, Spec::Prague, Spec::Osaka];
type Accounts = BTreeMap<H160, MemoryAccount>;

fn account(code: Vec<u8>) -> MemoryAccount {
    MemoryAccount {
        code,
        ..MemoryAccount::default()
    }
}

fn pre_state(code: Vec<u8>, target: H160, spec: Spec) -> Accounts {
    let mut pre = BTreeMap::from([
        (
            PROBER,
            MemoryAccount {
                nonce: U256::one(),
                ..account(code)
            },
        ),
        (target, account(TARGET_CODE.to_vec())),
    ]);
    if spec >= Spec::Prague {
        for address in [
            WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
        ] {
            pre.insert(address, account(vec![0x00]));
        }
    }
    pre
}

/// Expected post-state and gas are supplied by the test, not computed by the executor.
fn fixture(
    mut pre: Accounts,
    mut post: Accounts,
    gas_limit: u64,
    gas_used: u64,
    spec: Spec,
) -> (Block, ExecutionWitness, UncompressedPublicKey, ChainSpec) {
    let (secret, key) = sender_key();
    let sender = address_from_uncompressed_public_key(&key.0);
    let balance = U256::from(10_000_000);
    pre.insert(
        sender,
        MemoryAccount {
            balance,
            ..MemoryAccount::default()
        },
    );
    post.insert(
        sender,
        MemoryAccount {
            balance: balance - U256::from(2 * gas_used),
            nonce: U256::one(),
            ..MemoryAccount::default()
        },
    );
    post.insert(
        H160::zero(),
        MemoryAccount {
            balance: U256::from(gas_used),
            ..MemoryAccount::default()
        },
    );
    let (root, mut witness) = witness_of(&pre);
    let mut parent = cancun_parent(root);
    parent.requests_hash = (spec >= Spec::Prague).then_some(EMPTY_REQUESTS_HASH);
    witness.headers.push(rlp::encode(&parent).to_vec());
    let tx = signed_call(&secret, PROBER, gas_limit);
    let mut block = cancun_child(&parent, H256::zero());
    block.header.requests_hash = parent.requests_hash;
    block.header.transactions_root = ordered_trie_root([tx.encoded_2718()]);
    block.header.receipts_root =
        receipts_root(&[Receipt::new(TxType::Legacy, true, gas_used, vec![])]);
    block.header.gas_used = gas_used;
    block.header.state_root = state_root(&post);
    block.body.transactions.push(tx);
    let mut chain = chain_spec();
    chain.spec = spec;
    for fork in [Spec::Prague, Spec::Osaka] {
        if spec >= fork {
            chain.hard_forks_timestamps.insert(fork, 0);
        }
    }
    (block, witness, key, chain)
}

fn omit_code(witness: &mut ExecutionWitness, code: &[u8]) {
    let before = witness.contract_codes.len();
    witness.contract_codes.retain(|bytes| bytes != code);
    assert!(
        witness.contract_codes.len() < before,
        "the witness contained the omitted code"
    );
}

fn assert_hash_only(
    (block, mut witness, key, chain): (Block, ExecutionWitness, UncompressedPublicKey, ChainSpec),
    omitted: &[u8],
) {
    let expected_root = block.header.state_root;
    let complete =
        stateless_validation(block.clone(), &[key], witness.clone(), chain.clone()).unwrap();
    omit_code(&mut witness, omitted);
    let sparse = stateless_validation(block, &[key], witness, chain).unwrap();
    assert_eq!(sparse.block_hash, complete.block_hash);
    assert_eq!(
        sparse.execution_output.result,
        complete.execution_output.result
    );
    assert_eq!(
        witness_state_root(&sparse.execution_output.state),
        Ok(expected_root)
    );
    assert!(
        !sparse
            .execution_output
            .state
            .codes
            .contains_key(&keccak256(omitted))
    );
}

#[test]
fn extcodehash_validates_without_contract_or_designator_bytes() {
    for spec in FORKS {
        for delegated in [false, true] {
            let mut code = vec![0x73];
            code.extend_from_slice(TARGET.as_bytes());
            code.extend_from_slice(&[0x3f, 0x5f, 0x55, 0x00]);
            let mut pre = pre_state(code, TARGET, spec);
            let omitted = if delegated {
                let mut designator = vec![0xef, 1, 0];
                designator.extend_from_slice(H160::repeat_byte(0xdd).as_bytes());
                designator
            } else {
                TARGET_CODE.to_vec()
            };
            pre.get_mut(&TARGET).unwrap().code = omitted.clone();
            let mut post = pre.clone();
            post.get_mut(&PROBER)
                .unwrap()
                .storage
                .insert(H256::zero(), keccak256(&omitted));
            // PUSH20 + cold EXTCODEHASH + PUSH0 + cold zero-to-nonzero SSTORE.
            let gas = 21_000 + 3 + 2_600 + 2 + 22_100;
            assert_hash_only(fixture(pre, post, 100_000, gas, spec), &omitted);
        }
    }
}

#[test]
fn selfdestruct_beneficiary_needs_no_code_even_when_code_alone_makes_it_exist() {
    for spec in FORKS {
        let mut code = vec![0x73];
        code.extend_from_slice(TARGET.as_bytes());
        code.push(0xff);
        let mut pre = pre_state(code, TARGET, spec);
        pre.get_mut(&PROBER).unwrap().balance = U256::from(5);
        let mut post = pre.clone();
        post.get_mut(&PROBER).unwrap().balance = U256::zero();
        post.get_mut(&TARGET).unwrap().balance = U256::from(5);
        assert_hash_only(fixture(pre, post, 100_000, 28_603, spec), TARGET_CODE);
    }
}

#[test]
fn create2_collision_validates_without_the_occupants_code() {
    let salt = H256::from_low_u64_be(0x5a);
    let mut preimage = vec![0xff];
    preimage.extend_from_slice(PROBER.as_bytes());
    preimage.extend_from_slice(salt.as_bytes());
    preimage.extend_from_slice(keccak256(&[]).as_bytes());
    let occupant = H160::from_slice(&keccak256(&preimage).as_bytes()[12..]);
    for spec in FORKS {
        let code = vec![
            0x60, 0x5a, 0x60, 0, 0x60, 0, 0x60, 0, 0xf5, 0x60, 0, 0x55, 0,
        ];
        let pre = pre_state(code, occupant, spec);
        let mut post = pre.clone();
        post.get_mut(&PROBER).unwrap().nonce = U256::from(2);
        // The collision burns forwarded gas; the retained 1/64 pays PUSH1 and a no-op SSTORE.
        let gas = 1_000_000 - (1_000_000 - 21_000 - 12 - 32_000) / 64 + 3 + 2_200;
        assert_hash_only(fixture(pre, post, 1_000_000, gas, spec), TARGET_CODE);
    }
}

#[test]
fn withdrawal_to_a_contract_validates_without_executing_its_code() {
    let pre = BTreeMap::from([(TARGET, account(TARGET_CODE.to_vec()))]);
    let (root, mut witness) = witness_of(&pre);
    let parent = cancun_parent(root);
    witness.headers.push(rlp::encode(&parent).to_vec());
    let mut block = cancun_child(&parent, H256::zero());
    let withdrawals = vec![Withdrawal {
        index: 0,
        validator_index: 1,
        address: TARGET,
        amount: 7,
    }];
    block.header.withdrawals_root = Some(ordered_trie_root(
        withdrawals
            .iter()
            .map(|w| rlp::encode(w).to_vec())
            .collect::<Vec<_>>(),
    ));
    block.body.withdrawals = Some(withdrawals);
    let mut post = pre;
    post.get_mut(&TARGET).unwrap().balance = U256::from(7_000_000_000u64);
    block.header.state_root = state_root(&post);
    let complete = stateless_validation(block.clone(), &[], witness.clone(), chain_spec()).unwrap();
    omit_code(&mut witness, TARGET_CODE);
    let sparse = stateless_validation(block, &[], witness, chain_spec()).unwrap();
    assert_eq!(
        sparse.execution_output.result,
        complete.execution_output.result
    );
    assert_eq!(
        witness_state_root(&sparse.execution_output.state),
        Ok(state_root(&post))
    );
}

#[test]
fn executed_sized_and_copied_code_remains_required() {
    let mut sized = vec![0x73];
    sized.extend_from_slice(TARGET.as_bytes());
    sized.extend_from_slice(&[0x3b, 0x50, 0]);
    let mut copied = vec![0x60, 1, 0x5f, 0x5f, 0x73];
    copied.extend_from_slice(TARGET.as_bytes());
    copied.extend_from_slice(&[0x3c, 0]);
    let mut called = vec![0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73];
    called.extend_from_slice(TARGET.as_bytes());
    called.extend_from_slice(&[0x61, 0xff, 0xff, 0xf1, 0x50, 0]);
    for spec in FORKS {
        for (code, gas) in [
            (sized.clone(), 23_605),
            (copied.clone(), 23_616),
            (called.clone(), 23_621),
        ] {
            let pre = pre_state(code, TARGET, spec);
            let (block, mut witness, key, chain) = fixture(pre.clone(), pre, 100_000, gas, spec);
            assert!(
                stateless_validation(block.clone(), &[key], witness.clone(), chain.clone()).is_ok()
            );
            omit_code(&mut witness, TARGET_CODE);
            assert_eq!(
                stateless_validation(block, &[key], witness, chain),
                Err(StatelessValidationError::Execution(
                    BlockExecutionError::MissingWitness(WitnessDbError::Code {
                        address: TARGET,
                        code_hash: keccak256(TARGET_CODE)
                    })
                ))
            );
        }
    }
}

#[test]
fn delegation_requires_both_the_designator_and_the_executed_code() {
    let delegate = H160::repeat_byte(0xdd);
    let mut designator = vec![0xef, 1, 0];
    designator.extend_from_slice(delegate.as_bytes());
    let mut code = vec![0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73];
    code.extend_from_slice(TARGET.as_bytes());
    code.extend_from_slice(&[0x61, 0xff, 0xff, 0xf1, 0x50, 0]);
    for spec in [Spec::Prague, Spec::Osaka] {
        let mut pre = pre_state(code.clone(), TARGET, spec);
        pre.get_mut(&TARGET).unwrap().code = designator.clone();
        pre.insert(delegate, account(TARGET_CODE.to_vec()));
        // A second cold access for the delegate, then its PUSH1 and the caller's POP.
        let (block, witness, key, chain) = fixture(pre.clone(), pre, 100_000, 26_221, spec);
        assert!(
            stateless_validation(block.clone(), &[key], witness.clone(), chain.clone()).is_ok()
        );
        for (address, omitted) in [(TARGET, designator.as_slice()), (delegate, TARGET_CODE)] {
            let mut incomplete = witness.clone();
            omit_code(&mut incomplete, omitted);
            assert_eq!(
                stateless_validation(block.clone(), &[key], incomplete, chain.clone()),
                Err(StatelessValidationError::Execution(
                    BlockExecutionError::MissingWitness(WitnessDbError::Code {
                        address,
                        code_hash: keccak256(omitted)
                    })
                ))
            );
        }
    }
}
