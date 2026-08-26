//! Consensus transaction types and their RLP encodings.
//!
//! Each concrete type contains exactly the fields that its EIP defines. Invalid combinations are
//! therefore unrepresentable—for example, [`TxEip4844`] and [`TxEip7702`] use `H160` rather than
//! `TxKind` because those transaction types cannot create contracts. This also makes both envelope
//! encoding and encoding for signing total over all representable values. Internal assertions guard
//! only encoder list completion and arity, which no transaction value can violate.
//!
//! Decoding produces a signed consensus type, which can be consumed into the union-shaped
//! [`TxEnv`](crate::transaction::TxEnv) used by execution. There is intentionally no reverse
//! conversion: fields absent from the consensus type are filled with their canonical absent values
//! during projection.
//!
//! # Field order
//!
//! Each type's field encoder fixes the consensus-critical field order:
//!
//! | Type | Fields (before the tail) |
//! |---|---|
//! | Legacy | `nonce, gas_price, gas_limit, to, value, data` |
//! | `0x01` | `chain_id, nonce, gas_price, gas_limit, to, value, data, access_list` |
//! | `0x02` | `chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list` |
//! | `0x03` | `0x02` fields, then `max_fee_per_blob_gas, blob_versioned_hashes` |
//! | `0x04` | `0x02` fields, then `authorization_list` |
//!
//! The encoding for signing ends after these fields (plus `chain_id, 0, 0` for legacy EIP-155); the
//! envelope appends `v, r, s` for legacy or `y_parity, r, s` for typed transactions. In dynamic-fee
//! transactions, `max_priority_fee_per_gas` precedes `max_fee_per_gas`.
//!
//! # Strictness
//!
//! Every decoded list is checked through `rlp_strict` to require both list shape and complete payload
//! coverage before its fields are read.

mod codec;
pub mod eip1559;
pub mod eip2930;
pub mod eip4844;
pub mod eip7702;
pub mod envelope;
pub mod legacy;

pub use codec::TxDecodeError;
pub use eip1559::{SignedTxEip1559, TxEip1559};
pub use eip2930::{SignedTxEip2930, TxEip2930};
pub use eip4844::{SignedTxEip4844, TxEip4844};
pub use eip7702::{SignedTxEip7702, TxEip7702};
pub use envelope::SignedTxEnvelope;
pub use legacy::{SignedTxLegacy, TxLegacy};
