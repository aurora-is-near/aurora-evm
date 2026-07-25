//! [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844

/// EIP-4844 constants
/// Gas consumption of a single data blob (== blob byte size).
pub const GAS_PER_BLOB: u64 = 1 << 17;
/// Max number of blobs per block: EIP-7691
pub const MAX_BLOBS_PER_BLOCK_ELECTRA: u64 = 9;
pub const MAX_BLOBS_PER_BLOCK_CANCUN: u64 = 6;
/// Target consumable blob gas for data blobs per block: EIP-7691
pub const TARGET_BLOB_GAS_PER_BLOCK: u64 = 786_432;
/// Minimum gas price for data blobs.
pub const MIN_BLOB_GASPRICE: u64 = 1;
/// Controls the maximum rate of change for blob gas price.
pub const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3_338_477;
/// First version of the blob.
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;
