//! Private streaming Keccak adapter; backend selection does not change trie construction.

#[cfg(not(feature = "tiny-keccak"))]
use sha3::Digest;
#[cfg(feature = "tiny-keccak")]
use tiny_keccak::Hasher;

#[cfg(not(feature = "tiny-keccak"))]
pub struct TrieHasher(sha3::Keccak256);

#[cfg(not(feature = "tiny-keccak"))]
impl TrieHasher {
    #[inline]
    pub(super) fn new() -> Self {
        Self(sha3::Keccak256::new())
    }

    #[inline]
    pub(super) fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    #[inline]
    pub(super) fn finalize_reset(&mut self) -> [u8; 32] {
        self.0.finalize_reset().into()
    }
}

#[cfg(feature = "tiny-keccak")]
pub struct TrieHasher(tiny_keccak::Keccak);

#[cfg(feature = "tiny-keccak")]
impl TrieHasher {
    #[inline]
    pub(super) fn new() -> Self {
        Self(tiny_keccak::Keccak::v256())
    }

    #[inline]
    pub(super) fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    #[inline]
    pub(super) fn finalize_reset(&mut self) -> [u8; 32] {
        let mut result = [0; 32];
        std::mem::replace(&mut self.0, tiny_keccak::Keccak::v256()).finalize(&mut result);
        result
    }
}

/// One-shot Keccak-256 through the configured backend.
#[inline]
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = TrieHasher::new();
    hasher.update(bytes);
    hasher.finalize_reset()
}
