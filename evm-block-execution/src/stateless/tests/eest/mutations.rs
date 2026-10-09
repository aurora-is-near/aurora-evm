//! Controlled corruptions of otherwise accepted EEST blocks, with exact error expectations.

use super::*;

/// Changes only post-execution commitments; signatures, state and execution inputs stay intact.
pub(super) fn check_header_mutations(
    raw: &[u8],
    chain: &ChainSpec,
    ancestors: &[Vec<u8>],
    state: &BTreeMap<H160, MemoryAccount>,
) -> Result<usize, String> {
    let original = Block::decode_exact(raw).map_err(|error| error.to_string())?;
    let (_, mut witness) = witness_of(state);
    witness.headers = ancestors.to_vec();
    let mut count = 0;

    for field in [
        Commitment::GasUsed,
        Commitment::ReceiptsRoot,
        Commitment::LogsBloom,
        Commitment::StateRoot,
        Commitment::RequestsHash,
    ] {
        let mut block = original.clone();
        let header = &mut block.header;
        let expected = match field {
            Commitment::GasUsed => {
                let got = header.gas_used;
                // Stay within the pre-validation limit and avoid increasing the encoded length.
                header.gas_used = if got == header.gas_limit {
                    got - 1
                } else {
                    got ^ 1
                };
                BlockExecutionError::GasUsedMismatch {
                    got,
                    expected: header.gas_used,
                }
            }
            Commitment::ReceiptsRoot => {
                let got = header.receipts_root;
                header.receipts_root.0[0] ^= 1;
                BlockExecutionError::ReceiptsRootMismatch {
                    got,
                    expected: header.receipts_root,
                }
            }
            Commitment::LogsBloom => {
                let got = header.logs_bloom.clone();
                header.logs_bloom.0[0] ^= 1;
                BlockExecutionError::LogsBloomMismatch {
                    got: Box::new(got),
                    expected: Box::new(header.logs_bloom.clone()),
                }
            }
            Commitment::StateRoot => {
                let got = header.state_root;
                header.state_root.0[0] ^= 1;
                BlockExecutionError::StateRootMismatch {
                    got,
                    expected: header.state_root,
                }
            }
            Commitment::RequestsHash => {
                let Some(got) = header.requests_hash else {
                    continue;
                };
                let mut changed = got;
                changed.0[0] ^= 1;
                header.requests_hash = Some(changed);
                BlockExecutionError::RequestsHashMismatch {
                    got: Some(got),
                    expected: Some(changed),
                }
            }
            // Blob gas is checked against the body before execution, not a post-only mutation.
            Commitment::BlobGasUsed => unreachable!(),
        };

        let recovered = recover_block(block).map_err(|error| error.to_string())?;
        let actual = stateless_validation_recovered(recovered, witness.clone(), chain.clone());
        match actual {
            Err(StatelessValidationError::PostExecution(error)) if error == expected => {}
            Err(error) => {
                return Err(format!(
                    "{field:?} mutation: expected {expected:?}, got {error:?}"
                ));
            }
            Ok(_) => return Err(format!("{field:?} mutation was accepted")),
        }
        count += 1;
    }

    Ok(count)
}

#[test]
fn mutations_reach_the_production_checks_on_a_valid_empty_block() {
    let parent = super::super::cancun_parent(crate::constants::EMPTY_ROOT_HASH);
    let mut block = super::super::cancun_child(&parent, H256::zero());
    block.header.state_root = crate::constants::EMPTY_ROOT_HASH;
    let chain = super::super::chain_spec();
    let ancestors = [rlp::encode(&parent).to_vec()];
    let raw = rlp::encode(&block);
    assert!(execute_block(Mode::Witness, &chain, &raw, &ancestors, &BTreeMap::new()).is_ok());
    assert_eq!(
        check_header_mutations(&raw, &chain, &ancestors, &BTreeMap::new()),
        Ok(4)
    );
}
