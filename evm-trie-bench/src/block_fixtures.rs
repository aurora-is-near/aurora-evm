//! Synthetic workloads with full-state/triehash oracles, plus an unmodified EEST block.

use crate::block_guest::{Input, chain};
use aurora_evm::backend::MemoryAccount;
use aurora_evm_block_execution::{
    block::{BlobExcessGasAndPrice, Block, BlockBody, BlockEnv, Header, UncompressedPublicKey},
    constants::{EMPTY_REQUESTS_HASH, EMPTY_ROOT_HASH},
    crypto::keccak256,
    executor::BlockExecutor,
    stateless_validation,
    transaction::{SignedTxEnvelope, SignedTxLegacy, TxKind, TxLegacy, TxSignature},
    trie::{TrieAccount, state_root, storage_root},
    withdrawal::Withdrawal,
    witness_backend::{RevealedAccount, WitnessBackend},
};
use aurora_evm_trie::sparse::reference::hashed_nodes;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub enum Workload {
    Replace,
    Noop,
    Delete,
    Create,
    EmptyAccounts,
    Recreate,
}

pub fn cases() -> Vec<(String, Input)> {
    let mut cases: Vec<_> = [
        (Workload::Replace, 1, 16, false),
        (Workload::Replace, 8, 32, false),
        (Workload::Replace, 16, 64, true),
        (Workload::Noop, 8, 32, true),
        (Workload::Delete, 8, 32, true),
        (Workload::Create, 8, 32, true),
        (Workload::EmptyAccounts, 16, 0, true),
        (Workload::Recreate, 4, 1, true),
    ]
    .into_iter()
    .map(|(work, accounts, slots, osaka)| {
        (
            format!(
                "{work:?}-{accounts}x{slots}-{}",
                if osaka { "Osaka" } else { "Cancun" }
            ),
            fixture(work, accounts, slots, osaka),
        )
    })
    .collect();
    cases.push(("EEST-Osaka-access-list".into(), official_fixture()));
    cases
}

/// Pinned, unmodified EEST header commitments and pre-state; no expected root comes from execution.
fn official_fixture() -> Input {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/block-osaka.json")).unwrap();
    let bytes =
        |v: &serde_json::Value| hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    let state: BTreeMap<_, _> = fixture["pre"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(address, account)| {
            (
                address.parse::<H160>().unwrap(),
                MemoryAccount {
                    nonce: account["nonce"].as_str().unwrap().parse().unwrap(),
                    balance: account["balance"].as_str().unwrap().parse().unwrap(),
                    code: bytes(&account["code"]),
                    storage: account["storage"]
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(k, v)| {
                            let key: U256 = k.parse().unwrap();
                            let value: U256 = v.as_str().unwrap().parse().unwrap();
                            (H256(key.to_big_endian()), H256(value.to_big_endian()))
                        })
                        .collect(),
                },
            )
        })
        .collect();
    let parent = Block::decode_exact(&bytes(&fixture["genesis"]))
        .unwrap()
        .header;
    let block_bytes = bytes(&fixture["block"]);
    let block = Block::decode_exact(&block_bytes).unwrap();
    let (root, nodes, codes) = witness(&state);
    assert_eq!(root, parent.state_root);
    assert_eq!(root, state_root(&state));
    let expected_hash = fixture["block_hash"]
        .as_str()
        .unwrap()
        .parse::<H256>()
        .unwrap();
    assert_eq!(block.header.hash_slow(), expected_hash);
    let keys = block
        .transactions()
        .iter()
        .map(|tx| {
            let sig = tx.signature();
            libsecp256k1::recover(
                &libsecp256k1::Message::parse(&tx.signature_hash().0),
                &libsecp256k1::Signature::parse_standard(&sig.rs_bytes()).unwrap(),
                &libsecp256k1::RecoveryId::parse(u8::from(sig.y_parity)).unwrap(),
            )
            .unwrap()
            .serialize()
            .to_vec()
        })
        .collect();
    Input {
        block: block_bytes,
        keys,
        nodes,
        codes,
        headers: vec![rlp::encode(&parent).to_vec()],
        osaka: true,
        with_stage_hook: true,
        expected_hash: expected_hash.0,
        expected_gas: block.gas_used,
    }
}

fn runtime(work: Workload, slots: u64) -> Vec<u8> {
    let value = match work {
        Workload::Noop => 1,
        Workload::Delete => 0,
        _ => 2,
    };
    let mut code = Vec::new();
    for slot in 0..slots {
        code.extend_from_slice(&[0x60, value, 0x7f]); // PUSH1 value, PUSH32 slot, SSTORE.
        code.extend_from_slice(H256::from_low_u64_be(slot).as_bytes());
        code.push(0x55);
    }
    // A non-empty receipt tests both bloom and encoded log data, including in creation init code.
    code.extend_from_slice(&[0x60, 0xab, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xa0, 0]);
    code
}

fn sign(tx: TxLegacy, secret: &libsecp256k1::SecretKey) -> SignedTxEnvelope {
    let mut signed = SignedTxEnvelope::Legacy(SignedTxLegacy {
        tx,
        signature: TxSignature::new(false, U256::one(), U256::one()),
    });
    let (signature, recovery) = libsecp256k1::sign(
        &libsecp256k1::Message::parse(&signed.signature_hash().0),
        secret,
    );
    let bytes = signature.serialize();
    let SignedTxEnvelope::Legacy(tx) = &mut signed else {
        unreachable!()
    };
    tx.signature = TxSignature::new(
        recovery.serialize() != 0,
        U256::from_big_endian(&bytes[..32]),
        U256::from_big_endian(&bytes[32..]),
    );
    signed
}

/// CREATE2 deploys the same child on each call. Nonempty calldata also calls its SELFDESTRUCT
/// runtime; the next transaction recreates it. EIP-6780 permits deleting same-transaction creations.
fn factory() -> Vec<u8> {
    // Init code: SSTORE(0, 1), then return PUSH20(beneficiary) SELFDESTRUCT.
    let mut init = vec![
        0x60, 1, 0x5f, 0x55, 0x60, 22, 0x60, 14, 0x5f, 0x39, 0x60, 22, 0x5f, 0xf3, 0x73,
    ];
    init.extend_from_slice(H160::from_low_u64_be(0x888).as_bytes());
    init.push(0xff);
    let len = u8::try_from(init.len()).unwrap();
    // Offsets are filled after the factory prefix is built, independently of instruction lengths.
    let mut code = vec![
        0x60, len, 0x60, 0, 0x5f, 0x39, 0x5f, 0x60, len, 0x5f, 0x5f, 0xf5, 0x36, 0x15, 0x60, 0,
        0x57, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x85, 0x62, 0x0f, 0x42, 0x40, 0xf1, 0x50,
    ];
    code[15] = u8::try_from(code.len()).unwrap();
    code.extend_from_slice(&[0x5b, 0x50, 0x00]);
    code[3] = u8::try_from(code.len()).unwrap();
    code.extend(init);
    code
}

fn fixture(work: Workload, count: u64, slots: u64, osaka: bool) -> Input {
    let secret = libsecp256k1::SecretKey::parse(&[1; 32]).unwrap();
    let key = UncompressedPublicKey(libsecp256k1::PublicKey::from_secret_key(&secret).serialize());
    let sender = key.address(0).unwrap();
    let mut state = BTreeMap::from([(
        sender,
        MemoryAccount {
            balance: U256::from(1_000_000_000_000_000_000u64),
            ..MemoryAccount::default()
        },
    )]);
    if osaka {
        use aurora_evm_block_execution::system_calls::{
            CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS, WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
        };
        // Synthetic deployments return no requests. The normal EVM/system-call path still runs.
        for address in [
            WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
        ] {
            state.insert(
                address,
                MemoryAccount {
                    nonce: U256::one(),
                    code: vec![0],
                    ..MemoryAccount::default()
                },
            );
        }
    }
    // Untouched accounts make a nontrivial authenticated backdrop; the witness is a full superset.
    for i in 0..128 {
        state.insert(
            H160::from_low_u64_be(0x10000 + i),
            MemoryAccount {
                balance: U256::one(),
                ..MemoryAccount::default()
            },
        );
    }
    let mut txs = Vec::new();
    let mut withdrawals = Vec::new();
    for i in 0..count {
        let address = H160::from_low_u64_be(0x1000 + i);
        if matches!(work, Workload::EmptyAccounts) {
            state.insert(address, MemoryAccount::default());
            withdrawals.push(Withdrawal {
                index: i,
                validator_index: i,
                address,
                amount: 0,
            });
            continue;
        }
        let create = matches!(work, Workload::Create);
        let recreate = matches!(work, Workload::Recreate);
        let code = if recreate {
            factory()
        } else {
            runtime(work, slots)
        };
        if !create {
            state.insert(
                address,
                MemoryAccount {
                    nonce: U256::one(),
                    code: code.clone(),
                    storage: (0..slots)
                        .map(|slot| (H256::from_low_u64_be(slot), H256::from_low_u64_be(1)))
                        .collect(),
                    ..MemoryAccount::default()
                },
            );
        }
        txs.push(sign(
            TxLegacy {
                chain_id: Some(1),
                nonce: U256::from(txs.len()),
                gas_price: U256::from(2),
                gas_limit: 2_000_000,
                to: if create {
                    TxKind::Create
                } else {
                    TxKind::Call(address)
                },
                value: U256::zero(),
                data: if create {
                    code
                } else if recreate {
                    vec![1]
                } else {
                    Vec::new()
                },
            },
            &secret,
        ));
        if recreate {
            txs.push(sign(
                TxLegacy {
                    chain_id: Some(1),
                    nonce: U256::from(txs.len()),
                    gas_price: U256::from(2),
                    gas_limit: 2_000_000,
                    to: TxKind::Call(address),
                    value: U256::zero(),
                    data: Vec::new(),
                },
                &secret,
            ));
        }
    }
    let (pre_root, nodes, codes) = witness(&state);
    assert_eq!(pre_root, state_root(&state));
    let parent = Header {
        number: 1,
        timestamp: 1,
        gas_limit: 100_000_000,
        state_root: pre_root,
        base_fee_per_gas: Some(1),
        withdrawals_root: Some(EMPTY_ROOT_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(H256::zero()),
        requests_hash: osaka.then_some(EMPTY_REQUESTS_HASH),
        ..Header::default()
    };
    let env = BlockEnv {
        block_number: U256::from(2),
        block_coinbase: H160::from_low_u64_be(0x888),
        block_timestamp: U256::from(2),
        block_difficulty: U256::zero(),
        block_gas_limit: parent.gas_limit,
        block_base_fee_per_gas: U256::one(),
        block_randomness: Some(H256::zero()),
        blob_excess_gas_and_price: Some(BlobExcessGasAndPrice {
            excess_blob_gas: 0,
            blob_gas_price: 1,
        }),
        parent_hash: parent.hash_slow(),
        parent_beacon_block_root: Some(H256::zero()),
        withdrawals: withdrawals.clone(),
    };
    if matches!(work, Workload::Recreate) {
        let backend = WitnessBackend::from_full_state(
            env.vicinity(1),
            state.clone(),
            BTreeMap::from([(1, parent.hash_slow())]),
        );
        let first = BlockExecutor::new(
            chain(osaka),
            env.clone(),
            vec![txs[0].clone().into_tx_env(sender)],
            backend,
        )
        .unwrap()
        .execute()
        .unwrap();
        assert!(
            matches!(
                first
                    .state
                    .accounts()
                    .get(&child_address(H160::from_low_u64_be(0x1000))),
                Some(RevealedAccount::Absent)
            ),
            "first transaction must destroy its newly created child"
        );
    }
    let backend = WitnessBackend::from_full_state(
        env.vicinity(1),
        state,
        BTreeMap::from([(1, parent.hash_slow())]),
    );
    let output = BlockExecutor::new(
        chain(osaka),
        env.clone(),
        txs.iter()
            .cloned()
            .map(|tx| tx.into_tx_env(sender))
            .collect(),
        backend,
    )
    .unwrap()
    .execute()
    .unwrap();
    assert!(
        output.result.receipts.iter().all(|r| r.success),
        "benchmark runtime must succeed"
    );
    let full: BTreeMap<_, _> = output
        .state
        .accounts()
        .iter()
        .filter_map(|(address, account)| {
            let RevealedAccount::Present(account) = account else {
                return None;
            };
            Some((
                *address,
                MemoryAccount {
                    nonce: account.nonce,
                    balance: account.balance,
                    code: output
                        .state
                        .codes
                        .get(&account.code_hash)
                        .cloned()
                        .unwrap_or_default(),
                    storage: account
                        .storage
                        .iter()
                        .filter(|(_, v)| !v.is_zero())
                        .map(|(k, v)| (*k, *v))
                        .collect(),
                },
            ))
        })
        .collect();
    if matches!(work, Workload::Recreate) {
        for i in 0..count {
            let address = H160::from_low_u64_be(0x1000 + i);
            let child = &full[&child_address(address)];
            assert_eq!(child.nonce, U256::one());
            assert_eq!(
                child.storage,
                BTreeMap::from([(H256::zero(), H256::from_low_u64_be(1))])
            );
            assert_eq!(full[&address].nonce, U256::from(3));
        }
    }
    // Independent full-map triehash roots, not the sparse updater or ordered builder under test.
    let receipts: Vec<_> = output.result.receipts.iter().map(|r| r.encoded()).collect();
    let transactions: Vec<_> = txs.iter().map(|tx| tx.encoded_2718()).collect();
    let withdrawal_bytes: Vec<_> = withdrawals
        .iter()
        .map(|w| rlp::encode(w).to_vec())
        .collect();
    let mut header = Header {
        parent_hash: parent.hash_slow(),
        number: 2,
        timestamp: 2,
        gas_limit: parent.gas_limit,
        beneficiary: env.block_coinbase,
        state_root: state_root(&full),
        gas_used: output.result.gas_used,
        transactions_root: H256(crate::baseline(
            &transactions.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )),
        receipts_root: H256(crate::baseline(
            &receipts.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )),
        withdrawals_root: Some(H256(crate::baseline(
            &withdrawal_bytes
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
        ))),
        base_fee_per_gas: Some(1),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(H256::zero()),
        requests_hash: osaka.then(|| output.result.requests.requests_hash()),
        ..Header::default()
    };
    for receipt in &output.result.receipts {
        header.logs_bloom.accrue_bloom(&receipt.bloom);
    }
    let block = Block::new(header, BlockBody::new(txs, Some(withdrawals)));
    let input = Input {
        block: rlp::encode(&block).to_vec(),
        keys: vec![key.0.to_vec(); block.transactions().len()],
        nodes,
        codes,
        headers: vec![rlp::encode(&parent).to_vec()],
        osaka,
        with_stage_hook: true,
        expected_hash: block.header.hash_slow().0,
        expected_gas: block.header.gas_used,
    };
    let witness = aurora_evm_block_execution::execution_types::witness::ExecutionWitness {
        state: input.nodes.clone(),
        contract_codes: input.codes.clone(),
        headers: input.headers.clone(),
        storage_keys: Vec::new(),
    };
    let keys = vec![key; input.keys.len()];
    let ordinary =
        stateless_validation(block.clone(), &keys, witness.clone(), chain(osaka)).unwrap();
    let profiled = aurora_evm_block_execution::profiling::stateless_validation_with_stage_hook(
        block,
        &keys,
        witness,
        chain(osaka),
        |_| {},
    )
    .unwrap();
    assert_eq!(ordinary, profiled);
    input
}

fn witness(state: &BTreeMap<H160, MemoryAccount>) -> (H256, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut nodes = Vec::new();
    let mut codes = Vec::new();
    let mut leaves = BTreeMap::new();
    for (address, account) in state {
        let slots = account
            .storage
            .iter()
            .filter(|(_, value)| !value.is_zero())
            .map(|(key, value)| {
                (
                    keccak256(key.as_bytes()).0.to_vec(),
                    rlp::encode(&U256::from_big_endian(value.as_bytes())).to_vec(),
                )
            })
            .collect();
        let (root, storage_nodes) = hashed_nodes(&slots);
        assert_eq!(H256(root), storage_root(&account.storage));
        nodes.extend(storage_nodes);
        if !account.code.is_empty() && !codes.contains(&account.code) {
            codes.push(account.code.clone());
        }
        leaves.insert(
            keccak256(address.as_bytes()).0.to_vec(),
            rlp::encode(&TrieAccount {
                nonce: account.nonce,
                balance: account.balance,
                storage_root: H256(root),
                code_hash: keccak256(&account.code),
                code_version: U256::zero(),
            })
            .to_vec(),
        );
    }
    let (root, state_nodes) = hashed_nodes(&leaves);
    nodes.extend(state_nodes);
    // Witnesses are sets of node preimages, even when several accounts share a storage trie.
    let nodes = nodes
        .into_iter()
        .map(|node| (keccak256(&node), node))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect();
    (H256(root), nodes, codes)
}

fn child_address(factory_address: H160) -> H160 {
    let code = factory();
    let mut preimage = vec![0xff];
    preimage.extend_from_slice(factory_address.as_bytes());
    preimage.extend_from_slice(&[0; 32]);
    preimage.extend_from_slice(keccak256(&code[usize::from(code[3])..]).as_bytes());
    H160::from_slice(&keccak256(&preimage).as_bytes()[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn integrated_fixtures_match_full_roots_with_and_without_stage_hooks() {
        for (_, mut input) in cases() {
            for with_stage_hook in [false, true] {
                input.with_stage_hook = with_stage_hook;
                let counter = Cell::new(0u64);
                let heap = Cell::new(0usize);
                crate::block_guest::run(
                    input.clone(),
                    || {
                        counter.set(counter.get() + 1);
                        counter.get()
                    },
                    || {
                        heap.set(heap.get() + 4);
                        heap.get()
                    },
                );
            }
        }
    }
}
