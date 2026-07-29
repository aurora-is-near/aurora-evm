//! Consensus encoding of a transaction: the preimage its sender signs, and its EIP-2718 envelope.
//!
//! Both encodings are the same list of fields; they differ only in the tail:
//!
//! - the **signing preimage** ends with the payload (and, for a legacy EIP-155 transaction, with
//!   `chain_id, 0, 0`), and is what gets hashed to produce the signature hash;
//! - the **envelope** replaces that tail with the signature (`v, r, s` for legacy, `y_parity, r, s`
//!   for typed transactions), and is what the transactions trie and the transaction hash are built
//!   from.
//!
//! Everything except a legacy transaction is prefixed with its EIP-2718 type byte. The field order
//! per type is consensus-critical and is fixed here:
//!
//! | Type | Fields (before the tail) |
//! |---|---|
//! | Legacy | `nonce, gas_price, gas_limit, to, value, data` |
//! | `0x01` | `chain_id, nonce, gas_price, gas_limit, to, value, data, access_list` |
//! | `0x02` | `chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list` |
//! | `0x03` | `0x02` fields, then `max_fee_per_blob_gas, blob_versioned_hashes` |
//! | `0x04` | `0x02` fields, then `authorization_list` |
//!
//! Note the fee order: `max_priority_fee_per_gas` precedes `max_fee_per_gas`, which is the reverse
//! of how the two are usually named together.

use crate::transaction::payload::TxPayload;
use crate::transaction::signature::TxSignature;
use crate::transaction::signed_authorization::SignedAuthorization;
use crate::transaction::{AccessList, TxKind, TxType};
use core::fmt;
use primitive_types::{H160, H256, U256};

/// Number of trailing items a signature adds to the field list.
const SIGNATURE_FIELDS: usize = 3;

/// A transaction whose fields cannot be encoded for its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxEncodeError {
    /// A typed transaction is missing the `chain_id` every type from EIP-2930 on requires.
    MissingChainId,
    /// A legacy or EIP-2930 transaction is missing `gas_price`.
    MissingGasPrice,
    /// A dynamic-fee transaction is missing `max_fee_per_gas`.
    MissingMaxFeePerGas,
    /// A dynamic-fee transaction is missing `max_priority_fee_per_gas`.
    MissingMaxPriorityFeePerGas,
    /// An EIP-4844 or EIP-7702 transaction is a contract creation, which those types forbid.
    CreateNotSupported(TxType),
    /// The `chain_id` is too large for a legacy `v` to fit in a `u64`.
    ChainIdTooLarge,
}

impl fmt::Display for TxEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingChainId => write!(f, "typed transaction is missing `chain_id`"),
            Self::MissingGasPrice => write!(f, "transaction is missing `gas_price`"),
            Self::MissingMaxFeePerGas => write!(f, "transaction is missing `max_fee_per_gas`"),
            Self::MissingMaxPriorityFeePerGas => {
                write!(f, "transaction is missing `max_priority_fee_per_gas`")
            }
            Self::CreateNotSupported(tx_type) => {
                write!(f, "{tx_type:?} transaction cannot be a contract creation")
            }
            Self::ChainIdTooLarge => write!(f, "`chain_id` is too large for a legacy `v`"),
        }
    }
}

impl core::error::Error for TxEncodeError {}

/// Encodes a transaction, with the signature (the EIP-2718 envelope) or without it (the signing
/// preimage).
pub fn encode(
    payload: &TxPayload,
    authorization_list: &[SignedAuthorization],
    signature: Option<&TxSignature>,
) -> Result<Vec<u8>, TxEncodeError> {
    let list = match payload.tx_type {
        TxType::Legacy => encode_legacy(payload, signature)?,
        TxType::Eip2930 => encode_eip2930(payload, signature)?,
        TxType::Eip1559 => encode_eip1559(payload, signature)?,
        TxType::Eip4844 => encode_eip4844(payload, signature)?,
        TxType::Eip7702 => encode_eip7702(payload, authorization_list, signature)?,
    };

    let list = list.out();
    // A legacy transaction is a bare RLP list; every later type is prefixed with its type byte.
    if payload.tx_type == TxType::Legacy {
        return Ok(list.to_vec());
    }
    let mut bytes = Vec::with_capacity(list.len() + 1);
    bytes.push(u8::from(payload.tx_type));
    bytes.extend_from_slice(&list);
    Ok(bytes)
}

/// Legacy: six payload fields, then either the EIP-155 chain-id tail or the signature.
fn encode_legacy(
    payload: &TxPayload,
    signature: Option<&TxSignature>,
) -> Result<rlp::RlpStream, TxEncodeError> {
    // Signed, or unsigned-but-EIP-155, both carry a three-item tail; a pre-EIP-155 preimage does
    // not.
    let has_tail = signature.is_some() || payload.chain_id.is_some();
    let mut stream = rlp::RlpStream::new_list(if has_tail { 6 + SIGNATURE_FIELDS } else { 6 });
    stream.append(&payload.nonce);
    stream.append(&payload.gas_price.ok_or(TxEncodeError::MissingGasPrice)?);
    stream.append(&payload.gas_limit);
    append_destination(&mut stream, payload.tx_kind);
    stream.append(&payload.value);
    stream.append(&payload.data);

    match signature {
        Some(signature) => {
            let v = signature
                .legacy_v(payload.chain_id)
                .ok_or(TxEncodeError::ChainIdTooLarge)?;
            stream.append(&v);
            stream.append(&signature.r);
            stream.append(&signature.s);
        }
        None => {
            if let Some(chain_id) = payload.chain_id {
                stream.append(&chain_id);
                stream.append(&0u8);
                stream.append(&0u8);
            }
        }
    }
    Ok(stream)
}

/// EIP-2930: legacy fields with a chain id in front and an access list at the end.
fn encode_eip2930(
    payload: &TxPayload,
    signature: Option<&TxSignature>,
) -> Result<rlp::RlpStream, TxEncodeError> {
    let mut stream = rlp::RlpStream::new_list(field_count(8, signature));
    stream.append(&payload.chain_id.ok_or(TxEncodeError::MissingChainId)?);
    stream.append(&payload.nonce);
    stream.append(&payload.gas_price.ok_or(TxEncodeError::MissingGasPrice)?);
    stream.append(&payload.gas_limit);
    append_destination(&mut stream, payload.tx_kind);
    stream.append(&payload.value);
    stream.append(&payload.data);
    append_access_list(&mut stream, &payload.access_list);
    append_signature(&mut stream, signature);
    Ok(stream)
}

/// EIP-1559: dynamic fees in place of `gas_price`.
fn encode_eip1559(
    payload: &TxPayload,
    signature: Option<&TxSignature>,
) -> Result<rlp::RlpStream, TxEncodeError> {
    let mut stream = rlp::RlpStream::new_list(field_count(9, signature));
    append_dynamic_fee_fields(&mut stream, payload, payload.tx_kind)?;
    append_access_list(&mut stream, &payload.access_list);
    append_signature(&mut stream, signature);
    Ok(stream)
}

/// EIP-4844: dynamic-fee fields, then the blob fee cap and the blob hashes.
fn encode_eip4844(
    payload: &TxPayload,
    signature: Option<&TxSignature>,
) -> Result<rlp::RlpStream, TxEncodeError> {
    // A blob transaction must have a destination; the type has no creation form.
    require_destination(payload.tx_kind, TxType::Eip4844)?;
    let mut stream = rlp::RlpStream::new_list(field_count(11, signature));
    append_dynamic_fee_fields(&mut stream, payload, payload.tx_kind)?;
    append_access_list(&mut stream, &payload.access_list);
    stream.append(&U256::from(payload.max_fee_per_blob_gas));
    append_blob_hashes(&mut stream, &payload.blob_versioned_hashes);
    append_signature(&mut stream, signature);
    Ok(stream)
}

/// EIP-7702: dynamic-fee fields, then the signed authorization tuples.
fn encode_eip7702(
    payload: &TxPayload,
    authorization_list: &[SignedAuthorization],
    signature: Option<&TxSignature>,
) -> Result<rlp::RlpStream, TxEncodeError> {
    // A set-code transaction must have a destination; the type has no creation form.
    require_destination(payload.tx_kind, TxType::Eip7702)?;
    let mut stream = rlp::RlpStream::new_list(field_count(10, signature));
    append_dynamic_fee_fields(&mut stream, payload, payload.tx_kind)?;
    append_access_list(&mut stream, &payload.access_list);
    stream.append_list(authorization_list);
    append_signature(&mut stream, signature);
    Ok(stream)
}

/// The seven fields every dynamic-fee type opens with, in consensus order.
fn append_dynamic_fee_fields(
    stream: &mut rlp::RlpStream,
    payload: &TxPayload,
    tx_kind: TxKind,
) -> Result<(), TxEncodeError> {
    stream.append(&payload.chain_id.ok_or(TxEncodeError::MissingChainId)?);
    stream.append(&payload.nonce);
    stream.append(
        &payload
            .max_priority_fee_per_gas
            .ok_or(TxEncodeError::MissingMaxPriorityFeePerGas)?,
    );
    stream.append(
        &payload
            .max_fee_per_gas
            .ok_or(TxEncodeError::MissingMaxFeePerGas)?,
    );
    stream.append(&payload.gas_limit);
    append_destination(stream, tx_kind);
    stream.append(&payload.value);
    stream.append(&payload.data);
    Ok(())
}

/// Total field count: the type's own fields plus the signature tail when one is present.
const fn field_count(fields: usize, signature: Option<&TxSignature>) -> usize {
    if signature.is_some() {
        fields + SIGNATURE_FIELDS
    } else {
        fields
    }
}

/// Appends `to`: the address, or an empty string for a contract creation.
fn append_destination(stream: &mut rlp::RlpStream, tx_kind: TxKind) {
    match tx_kind.to() {
        Some(to) => {
            stream.append(to);
        }
        None => {
            stream.append_empty_data();
        }
    }
}

/// Requires a destination address, for the types that have no creation form.
fn require_destination(tx_kind: TxKind, tx_type: TxType) -> Result<H160, TxEncodeError> {
    tx_kind
        .to()
        .copied()
        .ok_or(TxEncodeError::CreateNotSupported(tx_type))
}

/// Appends the access list: a list of `[address, [storage_key, ...]]` pairs.
fn append_access_list(stream: &mut rlp::RlpStream, access_list: &AccessList) {
    stream.begin_list(access_list.len());
    for item in access_list.iter() {
        stream.begin_list(2);
        stream.append(&item.address);
        stream.append_list(&item.storage_keys);
    }
}

/// Appends the blob versioned hashes as fixed 32-byte strings.
///
/// They are held as `U256`, so they must be widened back to 32 bytes: encoding them as integers
/// would strip the leading zeros of any hash whose first byte is zero.
fn append_blob_hashes(stream: &mut rlp::RlpStream, hashes: &[U256]) {
    stream.begin_list(hashes.len());
    for hash in hashes {
        stream.append(&H256(hash.to_big_endian()));
    }
}

/// Appends `y_parity, r, s` for a typed transaction, or nothing when encoding a preimage.
fn append_signature(stream: &mut rlp::RlpStream, signature: Option<&TxSignature>) {
    if let Some(signature) = signature {
        stream.append(&signature.y_parity);
        stream.append(&signature.r);
        stream.append(&signature.s);
    }
}
