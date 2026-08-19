//! One module per transaction type: the fields that type actually has, and its RLP.
//!
//! # The consensus form
//!
//! These are the types a block body carries and the bytes are made from. Each holds exactly its own
//! fields, so:
//!
//! - RLP encoding is **total** — a type that cannot contradict itself cannot fail to encode, which is
//!   what lets [`Block`](crate::block::Block) implement `rlp::Encodable` at all;
//! - a destination a type forbids is unrepresentable ([`TxEip4844`] and [`TxEip7702`] hold an `H160`,
//!   not a `TxKind`), so the case is gone rather than checked;
//! - each type's tests live with it instead of in one pile.
//!
//! # One direction only
//!
//! Bytes decode into a typed transaction, and a typed transaction projects into
//! [`TxEnv`](crate::transaction::TxEnv) — the union execution reads. There is **no impl
//! back**, and that is the point: the projection writes every field the type does not have as its own
//! absent value, so a payload claiming a field its `tx_type` forbids is not rejected, it is
//! unreachable.
//!
//! ```text
//! bytes ──strict RLP──▶ SignedTx* ──projection──▶ TxEnv
//!       ◀── total RLP──            (no way back)
//! ```
//!
//! Encoding is therefore total in both places that matter: the EIP-2718 envelope the transactions
//! trie is built from, and the signing preimage the sender is recovered from. Neither can fail, so
//! neither forces a `Result` on the block codec above them.
//!
//! The split is the point: the type that carries a transaction's bytes and the type an interpreter
//! reads are different shapes with different jobs, and only one of them is authoritative.
//!
//! # Field order
//!
//! Consensus-critical, and fixed by each type's `append_fields`:
//!
//! | Type | Fields (before the tail) |
//! |---|---|
//! | Legacy | `nonce, gas_price, gas_limit, to, value, data` |
//! | `0x01` | `chain_id, nonce, gas_price, gas_limit, to, value, data, access_list` |
//! | `0x02` | `chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list` |
//! | `0x03` | `0x02` fields, then `max_fee_per_blob_gas, blob_versioned_hashes` |
//! | `0x04` | `0x02` fields, then `authorization_list` |
//!
//! Note the fee order: `max_priority_fee_per_gas` precedes `max_fee_per_gas`, the reverse of how the
//! two are usually named together.
//!
//! The tail is what separates the two encodings: the signing preimage ends with the fields above
//! (plus `chain_id, 0, 0` for a legacy EIP-155 transaction), the envelope ends with the signature
//! (`v, r, s` for legacy, `y_parity, r, s` for typed).
//!
//! # Strictness
//!
//! Every list read here goes through `rlp_strict`: `rlp`'s own walk stops silently at the first
//! unparseable item, so a list must be proven to be a list whose items tile its payload before its
//! contents mean anything.

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
