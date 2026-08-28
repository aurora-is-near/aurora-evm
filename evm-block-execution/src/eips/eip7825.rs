//! [EIP-7825] per-transaction gas limit introduced in Osaka.
//!
//! [EIP-7825]: https://eips.ethereum.org/EIPS/eip-7825

/// Maximum gas a transaction may declare (`2^24`).
pub const TX_GAS_LIMIT_CAP: u64 = 16_777_216;
