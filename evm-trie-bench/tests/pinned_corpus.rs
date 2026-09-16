//! Every maintained builder must match each external commitment, not only a shared workload.

#![cfg(feature = "corpus")]

use aurora_evm_trie_bench::{IMPLEMENTATIONS, cases};

#[test]
fn every_pinned_root_matches_all_three_builders() {
    let cases = cases();
    assert_eq!(
        cases.len(),
        29,
        "the pinned EEST corpus must remain complete"
    );
    assert_eq!(IMPLEMENTATIONS.len(), 3);
    for case in cases {
        let expected: [u8; 32] = hex::decode(&case.root).unwrap().try_into().unwrap();
        let values: Vec<_> = case
            .values
            .iter()
            .map(|value| hex::decode(value).unwrap())
            .collect();
        let slices: Vec<_> = values.iter().map(Vec::as_slice).collect();
        for (name, calculate) in IMPLEMENTATIONS {
            assert_eq!(
                calculate(&slices),
                expected,
                "{name}: {} ({})",
                case.source,
                case.kind
            );
        }
    }
}
