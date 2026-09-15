//! Opt-in length and body-root differential over every positive EEST blockchain fixture.

use super::super::{Spec, calculate_body_metrics};
use crate::block::Block;
use std::path::Path;

fn collect_files(directory: &Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, paths);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
}

#[test]
#[ignore = "requires EEST_PATH pointing to the official fixtures release"]
fn eest_body_lengths_and_roots_match_every_positive_block() {
    let directory = std::env::var("EEST_PATH").expect("set EEST_PATH to fixtures_stable-v5.4.0");
    let mut paths = Vec::new();
    collect_files(&Path::new(&directory).join("blockchain_tests"), &mut paths);

    assert!(!paths.is_empty(), "no EEST blockchain fixtures found");

    paths.sort();
    let (mut blocks_checked, mut transactions_checked, mut negative_blocks) = (0, 0, 0);
    let mut types = Vec::new();
    for path in paths {
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for (name, fixture) in json.as_object().unwrap() {
            for block in fixture["blocks"].as_array().unwrap() {
                if block.get("expectException").is_some() {
                    negative_blocks += 1;
                    continue;
                }
                let raw =
                    hex::decode(block["rlp"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                let decoded = Block::decode_exact(&raw).unwrap_or_else(|error| {
                    panic!("{}::{name}: {error}", path.display());
                });
                for tx in decoded.transactions() {
                    assert_eq!(
                        tx.encoded_2718_length(),
                        Some(tx.encoded_2718().len()),
                        "{name}"
                    );

                    if !types.contains(&tx.tx_type()) {
                        types.push(tx.tx_type());
                    }
                    transactions_checked += 1;
                }

                // This test covers representation, not fork validity; size limits are tested
                // separately. Pre-Osaka metrics accept every supported historical header shape.
                let metrics =
                    calculate_body_metrics(&decoded.header, &decoded.body, Spec::Prague).unwrap();

                assert_eq!(metrics.block_rlp_length, raw.len(), "{name}");
                assert_eq!(
                    metrics.transactions_root, decoded.header.transactions_root,
                    "{name}"
                );
                assert_eq!(
                    metrics.withdrawals_root, decoded.header.withdrawals_root,
                    "{name}"
                );

                blocks_checked += 1;
            }
        }
    }

    assert!(blocks_checked > 0 && transactions_checked > 0);
    assert_eq!(
        types.len(),
        5,
        "all supported transaction types must be represented"
    );

    eprintln!(
        "blocks={blocks_checked}, transactions={transactions_checked}, negative_blocks={negative_blocks}, types={types:?}"
    );
}
