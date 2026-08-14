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

pub mod eip1559;
pub mod eip2930;
pub mod eip4844;
pub mod eip7702;
pub mod envelope;
pub mod legacy;

use crate::rlp_strict;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, AccessListItem, TxKind, TxType};
use primitive_types::{H160, H256, U256};

pub use eip1559::{SignedTxEip1559, TxEip1559};
pub use eip2930::{SignedTxEip2930, TxEip2930};
pub use eip4844::{SignedTxEip4844, TxEip4844};
pub use eip7702::{SignedTxEip7702, TxEip7702};
pub use envelope::SignedTxEnvelope;
pub use legacy::{SignedTxLegacy, TxLegacy};

/// Why a transaction could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxDecodeError {
    /// The input carried no bytes.
    Empty,
    /// The leading byte is not a known EIP-2718 type and not an RLP list header.
    UnknownTxType(u8),
    /// The input is not well-formed RLP for its transaction type.
    Rlp(rlp::DecoderError),
    /// A legacy `v` that encodes neither a pre-EIP-155 parity nor a chain id.
    InvalidLegacyV(u128),
    /// A typed transaction's `y_parity` was neither `0` nor `1`.
    InvalidYParity(u8),
    /// A body item that is a byte string did not wrap an EIP-2718 envelope: a legacy transaction
    /// must appear as a bare RLP list, so wrapping one would give the block two encodings.
    WrappedLegacy,
    /// The `to` field was neither empty nor a 20-byte address.
    InvalidDestination,
    /// The transaction is a creation, which its type forbids.
    CreateNotSupported(TxType),
    /// `max_fee_per_blob_gas` does not fit in a `u128`.
    BlobFeeTooLarge,
}

impl From<rlp::DecoderError> for TxDecodeError {
    fn from(error: rlp::DecoderError) -> Self {
        Self::Rlp(error)
    }
}

impl core::fmt::Display for TxDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "no bytes to decode"),
            Self::UnknownTxType(byte) => write!(f, "unknown transaction type byte {byte:#04x}"),
            Self::Rlp(error) => write!(f, "malformed transaction RLP: {error}"),
            Self::InvalidLegacyV(v) => write!(f, "legacy signature `v` {v} is out of range"),
            Self::InvalidYParity(parity) => write!(f, "`y_parity` {parity} is not 0 or 1"),
            Self::WrappedLegacy => write!(
                f,
                "a legacy transaction must not be wrapped in an RLP byte string"
            ),
            Self::InvalidDestination => write!(f, "`to` is neither empty nor a 20-byte address"),
            Self::CreateNotSupported(tx_type) => {
                write!(f, "{tx_type:?} transaction cannot be a contract creation")
            }
            Self::BlobFeeTooLarge => write!(f, "`max_fee_per_blob_gas` does not fit in a u128"),
        }
    }
}

impl core::error::Error for TxDecodeError {}

/// Requires the item count an encoding of this type must have.
pub(super) fn expect_items(rlp: &rlp::Rlp<'_>, expected: usize) -> Result<(), TxDecodeError> {
    if rlp_strict::checked_len(rlp)? == expected {
        Ok(())
    } else {
        Err(TxDecodeError::Rlp(rlp::DecoderError::RlpIncorrectListLen))
    }
}

/// Decodes `to`: an address, or a contract creation when the field is empty.
pub(super) fn decode_destination(
    rlp: &rlp::Rlp<'_>,
    index: usize,
) -> Result<TxKind, TxDecodeError> {
    let bytes: Vec<u8> = rlp.val_at(index)?;
    if bytes.is_empty() {
        return Ok(TxKind::Create);
    }
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| TxDecodeError::InvalidDestination)?;
    Ok(TxKind::Call(H160(address)))
}

/// Decodes `to` for a type that has no creation form.
pub(super) fn decode_required_destination(
    rlp: &rlp::Rlp<'_>,
    index: usize,
    tx_type: TxType,
) -> Result<H160, TxDecodeError> {
    match decode_destination(rlp, index)? {
        TxKind::Create => Err(TxDecodeError::CreateNotSupported(tx_type)),
        TxKind::Call(to) => Ok(to),
    }
}

/// Appends `to`: the address, or an empty string for a contract creation.
pub(super) fn append_destination(stream: &mut rlp::RlpStream, tx_kind: TxKind) {
    match tx_kind.to() {
        Some(to) => stream.append(to),
        None => stream.append_empty_data(),
    };
}

/// Decodes the access list: a list of `[address, [storage_key, ...]]` pairs.
pub(super) fn decode_access_list(
    rlp: &rlp::Rlp<'_>,
    index: usize,
) -> Result<AccessList, TxDecodeError> {
    let list = rlp.at(index)?;
    let mut items = Vec::with_capacity(rlp_strict::checked_len(&list)?);
    for item in &list {
        if rlp_strict::checked_len(&item)? != 2 {
            return Err(TxDecodeError::Rlp(rlp::DecoderError::RlpIncorrectListLen));
        }
        items.push(AccessListItem {
            address: item.val_at(0)?,
            storage_keys: rlp_strict::checked_list_at(&item, 1)?,
        });
    }
    Ok(AccessList(items))
}

/// Appends the access list: a list of `[address, [storage_key, ...]]` pairs.
pub(super) fn append_access_list(stream: &mut rlp::RlpStream, access_list: &AccessList) {
    stream.begin_list(access_list.len());
    for item in access_list.iter() {
        stream.begin_list(2);
        stream.append(&item.address);
        stream.append_list(&item.storage_keys);
    }
}

/// Decodes a typed transaction's `y_parity, r, s` tail.
pub(super) fn decode_signature(
    rlp: &rlp::Rlp<'_>,
    index: usize,
) -> Result<TxSignature, TxDecodeError> {
    let parity: u8 = rlp.val_at(index)?;
    let y_parity = match parity {
        0 => false,
        1 => true,
        _ => return Err(TxDecodeError::InvalidYParity(parity)),
    };
    Ok(TxSignature::new(
        y_parity,
        rlp.val_at(index + 1)?,
        rlp.val_at(index + 2)?,
    ))
}

/// Appends a typed transaction's `y_parity, r, s` tail.
pub(super) fn append_signature(stream: &mut rlp::RlpStream, signature: &TxSignature) {
    stream.append(&signature.y_parity);
    stream.append(&signature.r);
    stream.append(&signature.s);
}

/// Decodes a `u128`-valued field that is encoded as an RLP integer.
pub(super) fn decode_u128(rlp: &rlp::Rlp<'_>, index: usize) -> Result<u128, TxDecodeError> {
    let value: U256 = rlp.val_at(index)?;
    if value.bits() > 128 {
        return Err(TxDecodeError::BlobFeeTooLarge);
    }
    Ok(value.low_u128())
}

/// Widens blob versioned hashes back to fixed 32-byte strings.
///
/// The flat form holds them as `U256`, so encoding them as integers would strip the leading zeros of
/// any hash whose first byte is zero.
pub(super) fn append_blob_hashes(stream: &mut rlp::RlpStream, hashes: &[H256]) {
    stream.begin_list(hashes.len());
    for hash in hashes {
        stream.append(hash);
    }
}
