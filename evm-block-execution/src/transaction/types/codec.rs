//! Shared RLP primitives for concrete transaction types.
//!
//! The helpers centralize field-count checks, destinations, access lists, signatures and fixed-width
//! blob hashes. Decoding keeps RLP payloads borrowed where possible and routes every nested list
//! through [`crate::rlp_strict`]; semantic errors that `rlp::DecoderError` cannot express are reported
//! as [`TxDecodeError`].

use crate::rlp_strict;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, AccessListItem, TxKind, TxType};
use primitive_types::{H160, H256, U256};

/// Why a transaction could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxDecodeError {
    /// The input carried no bytes.
    Empty,
    /// The leading byte is in EIP-2718's typed range but is not a supported transaction type.
    UnknownTxType(u8),
    /// The leading byte is neither an EIP-2718 type byte nor a legacy RLP list prefix.
    InvalidEnvelopePrefix(u8),
    /// The `0xff` extension sentinel reserved by EIP-2718.
    ReservedSentinel,
    /// The input is not well-formed RLP for its transaction type.
    Rlp(rlp::DecoderError),
    /// A legacy `v` that encodes neither a pre-EIP-155 parity nor a chain id.
    InvalidLegacyV(u128),
    /// A typed transaction's `y_parity` was neither `0` nor `1`.
    InvalidYParity(u8),
    /// A block-body byte string starts with a legacy RLP-list prefix (`0xc0..=0xfe`) instead of an
    /// EIP-2718 transaction type. The byte-string form is reserved for typed envelopes; a legacy
    /// transaction must be the bare list. Accepting a wrapped valid legacy list would give the same
    /// transaction two block encodings.
    LegacyInTypedBlockItem,
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
            Self::InvalidEnvelopePrefix(byte) => write!(
                f,
                "byte {byte:#04x} is neither an EIP-2718 type nor a legacy transaction prefix"
            ),
            Self::ReservedSentinel => write!(f, "EIP-2718 prefix 0xff is reserved"),
            Self::Rlp(error) => write!(f, "malformed transaction RLP: {error}"),
            Self::InvalidLegacyV(v) => write!(f, "legacy signature `v` {v} is out of range"),
            Self::InvalidYParity(parity) => write!(f, "`y_parity` {parity} is not 0 or 1"),
            Self::LegacyInTypedBlockItem => write!(
                f,
                "block-body byte string starts with a legacy RLP list; expected an EIP-2718 typed envelope"
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
///
/// The RLP payload stays borrowed while its width is checked, so an invalid `to` as large as the
/// input is rejected without first allocating and copying it.
pub(super) fn decode_destination(
    rlp: &rlp::Rlp<'_>,
    index: usize,
) -> Result<TxKind, TxDecodeError> {
    let destination = rlp.at(index)?.decoder().decode_value(|bytes| {
        Ok(match bytes.len() {
            0 => Some(TxKind::Create),
            20 => Some(TxKind::Call(H160::from_slice(bytes))),
            _ => None,
        })
    })?;
    destination.ok_or(TxDecodeError::InvalidDestination)
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
    rlp_strict::checked_len(&list)?;
    // Validate up front, but do not preallocate from an untrusted RLP item count (with `Vec::with_capacity`).
    let mut items = Vec::new();
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

#[cfg(test)]
mod tests {
    use super::{TxDecodeError, decode_destination, decode_required_destination};
    use crate::transaction::{TxKind, TxType};
    use hex_literal::hex;
    use primitive_types::H160;

    /// Decodes `raw` as a `to` field, by making it the only item of a one-item list.
    ///
    /// Asking about the field in isolation rather than through a whole transaction, because the width
    /// verdict is the field's own and every transaction type routes into the same helper.
    fn destination_of(raw: &[u8]) -> Result<TxKind, TxDecodeError> {
        let mut stream = rlp::RlpStream::new_list(1);
        stream.append_raw(raw, 1);
        let bytes = stream.out().to_vec();
        decode_destination(&rlp::Rlp::new(&bytes), 0)
    }

    /// `to` is empty for a creation and exactly twenty bytes for a call, and the width is what
    /// decides which — so a wrong width must be refused rather than padded or truncated into an
    /// address the sender never signed.
    #[test]
    fn a_destination_is_empty_or_exactly_twenty_bytes() {
        assert_eq!(destination_of(&hex!("80")).unwrap(), TxKind::Create);

        let address = hex!("ef2d6d194084c2de36e0dabfce45d046b37d1106");
        assert_eq!(
            destination_of(&rlp::encode(&address.to_vec())).unwrap(),
            TxKind::Call(H160(address))
        );

        for width in [1usize, 19, 21, 32] {
            assert_eq!(
                destination_of(&rlp::encode(&vec![0xaa; width])).unwrap_err(),
                TxDecodeError::InvalidDestination,
                "{width}-byte destination"
            );
        }
    }

    /// A malformed or non-canonical `to` is an RLP fault, not a width verdict.
    ///
    /// Keeping the two apart matters because `InvalidDestination` means "a well-formed string of the
    /// wrong width": reporting a decoder fault under that name would present a malformed input as a
    /// consensus judgement about an address. Both cases here are ones `Rlp::data()` would have
    /// accepted silently.
    #[test]
    fn a_malformed_destination_is_an_rlp_fault_not_an_invalid_address() {
        assert_eq!(
            destination_of(&hex!("8101")).unwrap_err(),
            TxDecodeError::Rlp(rlp::DecoderError::RlpInvalidIndirection)
        );

        let list = rlp::RlpStream::new_list(0).out().to_vec();
        assert_eq!(
            destination_of(&list).unwrap_err(),
            TxDecodeError::Rlp(rlp::DecoderError::RlpExpectedToBeData)
        );
    }

    /// The types that have no creation form reject an empty `to` at decode time, so the case is gone
    /// from their payloads rather than checked later.
    #[test]
    fn a_type_without_a_creation_form_rejects_an_empty_destination() {
        let mut stream = rlp::RlpStream::new_list(1);
        stream.append_raw(&hex!("80"), 1);
        let bytes = stream.out().to_vec();

        for tx_type in [TxType::Eip4844, TxType::Eip7702] {
            assert_eq!(
                decode_required_destination(&rlp::Rlp::new(&bytes), 0, tx_type).unwrap_err(),
                TxDecodeError::CreateNotSupported(tx_type),
                "{tx_type:?}"
            );
        }
    }
}
