//! Protocol constants and formulas, grouped by EIP.
//!
//! Transaction fields remain in [`transaction::types`](crate::transaction::types); this module owns
//! shared arithmetic such as base fees, blob gas, schedules and limits.

pub mod eip1559;
pub mod eip4844;
pub mod eip7594;
pub mod eip7691;
pub mod eip7825;
pub mod eip7840;
pub mod eip7892;
