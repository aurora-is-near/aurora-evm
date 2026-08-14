//! Constants and formulas defined by the EIPs this crate implements, one module per EIP.
//!
//! Protocol arithmetic and its numbers live here — base fees, blob gas, schedules, limits. The
//! consensus *fields* an EIP adds to a transaction live with that transaction instead, in
//! [`transaction::types`](crate::transaction::types), so EIP-4844 appears in both places: its blob
//! gas maths here, its `blob_versioned_hashes` there.

pub mod eip1559;
pub mod eip4844;
pub mod eip7594;
pub mod eip7691;
pub mod eip7825;
pub mod eip7840;
pub mod eip7892;
