//! Opt-in end-to-end comparison, including length checks, encoding and owned baseline leaves.
//! The baseline preserves the pre-optimization metrics flow; it deliberately uses triehash.

use super::super::{
    BlockBody, BlockValidationError, BodyMetrics, Header, SignedTxEnvelope, Spec, TxType,
    add_blob_count, calculate_blob_gas_used, calculate_block_rlp_length, calculate_body_metrics,
    validate_block_size,
};
use crate::rlp_strict::list_length;
use crate::withdrawal::Withdrawal;
use primitive_types::{H160, H256};

fn ordered_trie_root<I, V>(items: I) -> H256
where
    I: IntoIterator<Item = V>,
    V: AsRef<[u8]>,
{
    triehash::ordered_trie_root::<crate::trie::KeccakHasher, _>(items)
}

fn baseline_metrics(
    header: &Header,
    body: &BlockBody,
    active_spec: Spec,
) -> Result<BodyMetrics, BlockValidationError> {
    let header_length = rlp::encode(header).len();

    let (withdrawal_values, withdrawals_length) = match body.withdrawals() {
        Some(withdrawals) => {
            let mut payload_length: usize = 0;
            let mut withdrawals_length = 1;
            let mut values = Vec::with_capacity(withdrawals.len());
            for (withdrawal_index, withdrawal) in withdrawals.iter().enumerate() {
                let value = rlp::encode(withdrawal);
                payload_length = payload_length
                    .checked_add(value.len())
                    .ok_or(BlockValidationError::WithdrawalsLengthOverflow { withdrawal_index })?;
                withdrawals_length = list_length(payload_length)
                    .ok_or(BlockValidationError::WithdrawalsLengthOverflow { withdrawal_index })?;

                if active_spec >= Spec::Osaka {
                    let rlp_length =
                        calculate_block_rlp_length(header_length, 0, withdrawals_length)?;
                    validate_block_size(rlp_length, active_spec)?;
                }
                values.push(value);
            }
            (Some(values), withdrawals_length)
        }
        None => (None, 0),
    };

    let mut scratch = rlp::RlpStream::new();
    let mut transactions_payload_length: usize = 0;
    let mut blob_count: u64 = 0;
    // The count is already backed by the materialized body, so exact reservation avoids leaking
    // growth allocations in a bump-allocated guest. Values reach `triehash` only after EIP-7934.
    let mut transaction_values = Vec::with_capacity(body.transactions.len());
    for (transaction_index, transaction) in body.transactions.iter().enumerate() {
        let envelope = transaction.encode_2718_in(&mut scratch);
        let block_item_length = if transaction.tx_type() == TxType::Legacy {
            envelope.len()
        } else {
            list_length(envelope.len()).ok_or(
                BlockValidationError::TransactionItemLengthOverflow {
                    transaction_index,
                    envelope_length: envelope.len(),
                },
            )?
        };
        transactions_payload_length = transactions_payload_length
            .checked_add(block_item_length)
            .ok_or(BlockValidationError::TransactionsLengthOverflow { transaction_index })?;

        if let SignedTxEnvelope::Eip4844(transaction) = transaction {
            blob_count = add_blob_count(
                blob_count,
                transaction.tx.blob_versioned_hashes.len(),
                transaction_index,
            )?;
        }
        if active_spec >= Spec::Osaka {
            let rlp_length = calculate_block_rlp_length(
                header_length,
                transactions_payload_length,
                withdrawals_length,
            )?;
            validate_block_size(rlp_length, active_spec)?;
        }
        transaction_values.push(envelope.to_vec());
    }

    let block_rlp_length = calculate_block_rlp_length(
        header_length,
        transactions_payload_length,
        withdrawals_length,
    )?;
    let blob_gas_used = calculate_blob_gas_used(blob_count)?;

    let transactions_root = ordered_trie_root(transaction_values);
    let withdrawals_root = withdrawal_values.map(ordered_trie_root);

    Ok(BodyMetrics {
        transactions_root,
        withdrawals_root,
        blob_gas_used,
        block_rlp_length,
    })
}

#[test]
#[ignore = "timing benchmark; run alone in release mode with --ignored --nocapture"]
fn body_metrics_benchmark() {
    use std::{
        hint::black_box,
        time::{Duration, Instant},
    };

    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../../../../testdata/ordered-roots.json")).unwrap();
    let case = cases
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["kind"] == "transactions")
        .max_by_key(|case| case["values"].as_array().unwrap().len())
        .unwrap();
    let pool: Vec<_> = case["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            SignedTxEnvelope::decode_2718(&hex::decode(value.as_str().unwrap()).unwrap()).unwrap()
        })
        .collect();
    let header = Header::default();
    for count in [0, 1, 200, 2000] {
        let body = BlockBody::new(
            (0..count).map(|i| pool[i % pool.len()].clone()).collect(),
            Some(
                (0..16)
                    .map(|index| Withdrawal {
                        index,
                        validator_index: index,
                        address: H160::zero(),
                        amount: 1,
                    })
                    .collect(),
            ),
        );
        let expected = baseline_metrics(&header, &body, Spec::Osaka).unwrap();
        let actual = calculate_body_metrics(&header, &body, Spec::Osaka).unwrap();

        assert_eq!(actual.transactions_root, expected.transactions_root);
        assert_eq!(actual.withdrawals_root, expected.withdrawals_root);
        assert_eq!(actual.block_rlp_length, expected.block_rlp_length);
        assert_eq!(actual.blob_gas_used, expected.blob_gas_used);

        let mut samples = [Vec::new(), Vec::new()];
        for round in 0..7 {
            for offset in 0..2 {
                let algorithm = (round + offset) % 2;
                let calculate = [baseline_metrics, calculate_body_metrics][algorithm];
                let start = Instant::now();
                let mut iterations = 0u32;
                while start.elapsed() < Duration::from_millis(40) {
                    black_box(
                        calculate(black_box(&header), black_box(&body), Spec::Osaka).unwrap(),
                    );
                    iterations += 1;
                }
                samples[algorithm].push(start.elapsed().as_nanos() / u128::from(iterations));
            }
        }
        for (name, mut times) in ["baseline", "streaming"].into_iter().zip(samples) {
            times.sort_unstable();

            println!(
                "body n={count} {name}: median={}ns min={}ns max={}ns",
                times[3], times[0], times[6]
            );
        }
    }
}
