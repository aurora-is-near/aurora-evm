//! Cryptographic hash helpers.
//!
//! `keccak256` is the workhorse (trie node hashing, code hashes, bloom bits, addresses).
//! `sha256` is used solely by the EIP-7685 `requests_hash` (which is sha256, not keccak).

use primitive_types::{H160, H256};
// `sha2` and `sha3` both re-export the same `digest::Digest` trait, so a single import
// brings `digest()` into scope for both hashers.
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// Computes the Keccak-256 hash of `bytes`.
#[must_use]
pub fn keccak256(bytes: &[u8]) -> H256 {
    H256::from_slice(Keccak256::digest(bytes).as_ref())
}

/// Derives an Ethereum address from the coordinates in a 65-byte SEC1-shaped public key.
///
/// This helper performs no key validation: callers must verify the leading `0x04` tag and curve
/// membership as appropriate. The tag is excluded from `keccak256`; the address is the low 20 bytes
/// of the coordinate hash.
#[must_use]
#[inline]
pub(crate) fn address_from_uncompressed_public_key(public_key: &[u8; 65]) -> H160 {
    let hash = keccak256(&public_key[1..]);
    H160::from_slice(&hash[12..])
}

/// Computes the SHA-256 hash of `bytes` (EIP-7685 `requests_hash`).
#[must_use]
pub fn sha256(bytes: &[u8]) -> H256 {
    H256::from_slice(Sha256::digest(bytes).as_ref())
}

#[cfg(test)]
mod tests {
    use super::{address_from_uncompressed_public_key, keccak256, sha256};
    use crate::constants::{EMPTY_REQUESTS_HASH, KECCAK_EMPTY};
    use hex_literal::hex;
    use primitive_types::H160;

    #[test]
    fn ethereum_address_matches_the_secp256k1_generator_key() {
        // Uncompressed public key for private key 1.
        let public_key = hex!(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
        assert_eq!(
            address_from_uncompressed_public_key(&public_key),
            H160(hex!("7e5f4552091a69125d5dfcb7b8c2659029395bdf"))
        );
    }

    #[test]
    fn keccak_of_empty_matches_constant() {
        assert_eq!(keccak256(&[]), KECCAK_EMPTY);
    }

    #[test]
    fn sha256_of_empty_matches_constant() {
        assert_eq!(sha256(&[]), EMPTY_REQUESTS_HASH);
    }

    #[test]
    fn keccak_known_vector() {
        // keccak256("abc")
        assert_eq!(
            hex::encode(keccak256(b"abc").as_bytes()),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn sha256_known_vector() {
        // sha256("abc")
        assert_eq!(
            hex::encode(sha256(b"abc").as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
