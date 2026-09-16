//! Ethereum ordered MPT roots over the keys `RLP(0..len)`.
//!
//! Values are consumed in lexicographic key order without sorting or retaining encoded leaves.
//! The builder uses bounded stack scratch through 65,536 items and a depth-sized heap buffer above
//! that. It does not support arbitrary or secure-trie keys.
//!
//! The default hash backend is `sha3`. The `tiny-keccak` feature selects the same Keccak-256
//! primitive through `tiny-keccak`; VM acceleration requires the guest's matching dependency patch.
//!
//! See the [algorithm and sources](#algorithm) below for the RLP-index specialization and its
//! relationship to the [Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).

#![forbid(unsafe_code)]
#![doc = include_str!("../ALGORITHM.md")]

mod crypto;
mod ordered;

const EMPTY_ROOT_HASH: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Computes the root over already encoded values, without copying them or materializing keys.
#[must_use]
pub fn ordered_trie_root<T: AsRef<[u8]>>(items: &[T]) -> [u8; 32] {
    ordered::root_of(items)
}

/// Encodes each item once into one reusable stream and consumes its slice immediately.
///
/// The encoder must clear the stream before writing. Calls follow RLP-key order, not item order;
/// the empty collection neither allocates a stream nor invokes the encoder.
#[must_use]
pub fn ordered_trie_root_with_encoder<T, F>(items: &[T], encode: F) -> [u8; 32]
where
    F: for<'s> FnMut(&T, &'s mut rlp::RlpStream) -> &'s [u8],
{
    ordered::root_with_encoder(items, encode)
}
