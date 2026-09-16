//! Independent EEST commitments through the public block-execution trie API.

use crate::trie::ordered_trie_root;

#[test]
fn pinned_eest_roots_are_reproduced() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/ordered-roots.json")).unwrap();
    let cases = cases.as_array().unwrap();
    assert!(!cases.is_empty());
    let mut largest = 0;
    for case in cases {
        let values: Vec<_> = case["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
            .collect();
        largest = largest.max(values.len());
        assert_eq!(
            hex::encode(ordered_trie_root(&values)),
            case["root"].as_str().unwrap(),
            "{}",
            case["source"]
        );
    }
    assert!(
        largest >= 129,
        "external roots must exercise multi-byte RLP indices"
    );
}
