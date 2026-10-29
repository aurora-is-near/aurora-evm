//! Full production validation with optional phase measurements; inputs are prepared on the host.

use aurora_evm_block_execution::{
    block::{Block, UncompressedPublicKey},
    chain_spec::ChainSpec,
    eips::{eip1559::BaseFeeParams, eip7892::BlobScheduleBlobParams},
    execution_types::witness::ExecutionWitness,
    profiling::stateless_validation_with_stage_hook,
    spec::Spec,
    stateless_validation,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Input {
    pub block: Vec<u8>,
    pub keys: Vec<Vec<u8>>,
    pub nodes: Vec<Vec<u8>>,
    pub codes: Vec<Vec<u8>>,
    pub headers: Vec<Vec<u8>>,
    pub osaka: bool,
    pub with_stage_hook: bool,
    pub expected_hash: [u8; 32],
    pub expected_gas: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Region {
    pub cycles: u64,
    /// Bump growth, including abandoned capacities; not peak live memory.
    pub heap: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    pub total: Region,
    /// Recovery, consensus, witness, execution, commitments, sparse root.
    pub phases: [Region; 6],
    pub block_hash: [u8; 32],
    pub gas_used: u64,
    pub receipts: usize,
}

pub fn chain(osaka: bool) -> ChainSpec {
    ChainSpec {
        chain_id: 1,
        spec: if osaka { Spec::Osaka } else { Spec::Cancun },
        hard_forks_timestamps: BTreeMap::from([
            (Spec::Cancun, 0),
            (Spec::Prague, if osaka { 0 } else { u64::MAX }),
            (Spec::Osaka, if osaka { 0 } else { u64::MAX }),
        ]),
        deposit_contract_address: None,
        base_fee_params: BaseFeeParams::ethereum(),
        blob_schedule: BlobScheduleBlobParams::mainnet(),
    }
}

/// The heap callback allocates a four-byte marker. Decoding is outside the measured region;
/// validation owns the prepared inputs, exactly as in the ordinary public entry point.
pub fn run(input: Input, cycles: impl Fn() -> u64, heap: impl Fn() -> usize) -> Output {
    let block = Block::decode_exact(&input.block).unwrap();
    let keys: Vec<_> = input
        .keys
        .iter()
        .map(|key| UncompressedPublicKey(key.as_slice().try_into().unwrap()))
        .collect();
    let witness = ExecutionWitness {
        state: input.nodes,
        contract_codes: input.codes,
        headers: input.headers,
        storage_keys: Vec::new(),
    };
    let chain = chain(input.osaka);
    let mut phases = [Region::default(); 6];
    let mut previous = None;
    let mut index = 0;
    let mut markers = 0;
    let before = heap();
    let start = cycles();
    let output = if input.with_stage_hook {
        stateless_validation_with_stage_hook(block, &keys, witness, chain, |_| {
            let end = cycles();
            let used = heap();
            markers += 1;
            if let Some((start, before)) = previous {
                phases[index] = Region {
                    cycles: end - start,
                    heap: used - before - 4,
                };
                index += 1;
            }
            previous = Some((cycles(), used));
        })
    } else {
        stateless_validation(block, &keys, witness, chain)
    }
    .unwrap();
    let total = Region {
        cycles: cycles() - start,
        heap: heap() - before - 4 * (markers + 1),
    };
    assert_eq!(index, if input.with_stage_hook { 6 } else { 0 });
    assert_eq!(output.block_hash.0, input.expected_hash);
    assert_eq!(output.execution_output.result.gas_used, input.expected_gas);
    Output {
        total,
        phases,
        block_hash: output.block_hash.0,
        gas_used: output.execution_output.result.gas_used,
        receipts: output.execution_output.result.receipts.len(),
    }
}
