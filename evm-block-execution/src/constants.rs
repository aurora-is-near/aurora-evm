//! Well-known constants used across block execution.

use hex_literal::hex;
use primitive_types::H256;

/// Number of recent ancestors available to the `BLOCKHASH` opcode.
pub const BLOCKHASH_WINDOW: usize = 256;

/// `keccak256("")` — the code hash of an account with empty code.
pub const KECCAK_EMPTY: H256 = H256(hex!(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
));

/// `sha256("")` — the EIP-7685 `requests_hash` of a block that has no requests.
pub const EMPTY_REQUESTS_HASH: H256 = H256(hex!(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
));

/// Root hash of an empty Merkle-Patricia trie (`keccak256(rlp("")) == keccak256(0x80)`).
pub const EMPTY_ROOT_HASH: H256 = H256(hex!(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
));

/// `keccak256(rlp([]))` — the `ommers_hash` of a block with no ommers (every post-merge block).
pub const EMPTY_OMMER_ROOT_HASH: H256 = H256(hex!(
    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
));
