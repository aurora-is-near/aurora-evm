//! Isolated comparison harness; the candidate is a normal dependency on the production crate.

pub mod crypto {
    impl Default for TrieHasher {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(not(feature = "tiny"))]
    pub struct TrieHasher(sha3::Keccak256);

    #[cfg(not(feature = "tiny"))]
    impl TrieHasher {
        pub fn new() -> Self {
            use sha3::Digest;
            Self(sha3::Keccak256::new())
        }
        pub fn update(&mut self, bytes: &[u8]) {
            use sha3::Digest;
            self.0.update(bytes);
        }
        pub fn finalize_reset(&mut self) -> [u8; 32] {
            use sha3::Digest;
            self.0.finalize_reset().into()
        }
    }

    #[cfg(feature = "tiny")]
    pub struct TrieHasher(tiny_keccak::Keccak);

    #[cfg(feature = "tiny")]
    impl TrieHasher {
        pub fn new() -> Self {
            Self(tiny_keccak::Keccak::v256())
        }
        pub fn update(&mut self, bytes: &[u8]) {
            use tiny_keccak::Hasher;
            self.0.update(bytes);
        }
        pub fn finalize_reset(&mut self) -> [u8; 32] {
            use tiny_keccak::Hasher;
            let mut out = [0; 32];
            std::mem::replace(&mut self.0, tiny_keccak::Keccak::v256()).finalize(&mut out);
            out
        }
    }
}

pub fn candidate(items: &[&[u8]]) -> [u8; 32] {
    aurora_evm_trie::ordered_trie_root(items)
}

pub fn encoded_candidate<T, F>(items: &[T], encode: F) -> [u8; 32]
where
    F: for<'s> FnMut(&T, &'s mut rlp::RlpStream) -> &'s [u8],
{
    aurora_evm_trie::ordered_trie_root_with_encoder(items, encode)
}

#[derive(Default, Debug)]
pub struct KeccakHasher;

impl hash_db::Hasher for KeccakHasher {
    type Out = [u8; 32];
    type StdHasher = plain_hasher::PlainHasher;
    const LENGTH: usize = 32;
    fn hash(bytes: &[u8]) -> Self::Out {
        let mut hash = crypto::TrieHasher::new();
        hash.update(bytes);
        hash.finalize_reset()
    }
}

pub fn baseline(items: &[&[u8]]) -> [u8; 32] {
    triehash::ordered_trie_root::<KeccakHasher, _>(items)
}

pub fn alloy(items: &[&[u8]]) -> [u8; 32] {
    if items.is_empty() {
        return alloy_trie::EMPTY_ROOT_HASH.0;
    }

    let mut builder = alloy_trie::HashBuilder::default();
    for i in 0..items.len() {
        let index = if i > 0x7f {
            i
        } else if i == 0x7f || i + 1 == items.len() {
            0
        } else {
            i + 1
        };
        let key = alloy_primitives::private::alloy_rlp::encode_fixed_size(&index);
        builder.add_leaf(alloy_trie::Nibbles::unpack(key), items[index]);
    }
    builder.root().0
}

pub type RootFunction = fn(&[&[u8]]) -> [u8; 32];
pub const IMPLEMENTATIONS: &[(&str, RootFunction)] = &[
    ("triehash", baseline),
    ("alloy", alloy),
    ("candidate", candidate),
];

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Case {
    pub source: String,
    pub kind: String,
    pub root: String,
    pub values: Vec<String>,
}

#[cfg(feature = "corpus")]
pub fn cases() -> Vec<Case> {
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../evm-block-execution/testdata/ordered-roots.json"
    ))
    .unwrap();
    assert!(
        !cases.is_empty(),
        "the pinned EEST corpus must not be empty"
    );
    cases
}

#[cfg(feature = "sparse")]
pub mod sparse;
