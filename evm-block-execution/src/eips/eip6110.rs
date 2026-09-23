//! [EIP-6110] deposit requests parsed from deposit-contract logs.
//!
//! The deposit contract emits `DepositEvent(bytes pubkey, bytes withdrawal_credentials,
//! bytes amount, bytes signature, bytes index)`. Every field has a fixed size, so the ABI layout
//! of a genuine event is one exact byte pattern: five offset words, then each field as a length
//! word followed by its zero-padded bytes. A log at the deposit address with the event topic but
//! any other layout makes the block invalid (execution-specs `parse_deposit_data`).
//!
//! The request data is the concatenation of the five raw fields (192 bytes per deposit), in log
//! order across the block's receipts.
//!
//! [EIP-6110]: https://eips.ethereum.org/EIPS/eip-6110

use crate::receipt::Receipt;
use aurora_evm::backend::Log;
use core::fmt;
use hex_literal::hex;
use primitive_types::{H160, H256};

#[cfg(test)]
mod tests;

/// Ethereum mainnet deposit contract, used when the chain configures no other address.
pub const MAINNET_DEPOSIT_CONTRACT_ADDRESS: H160 =
    H160(hex!("00000000219ab540356cbb839cbe05303d7705fa"));

/// `keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)")`, the event's first topic.
pub const DEPOSIT_EVENT_SIGNATURE_HASH: H256 = H256(hex!(
    "649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"
));

/// Size of one deposit request: pubkey, withdrawal credentials, amount, signature and index.
pub const DEPOSIT_REQUEST_LENGTH: usize = 48 + 32 + 8 + 96 + 8;

/// Length of the ABI-encoded event data: five offset words plus each field's word-aligned slot.
const DEPOSIT_LOG_DATA_LENGTH: usize = 576;

/// The five dynamic fields with their canonical offset word and fixed size. The offset doubles as
/// the position of the field's length word.
const FIELDS: [(DepositField, usize, usize); 5] = [
    (DepositField::Pubkey, 160, 48),
    (DepositField::WithdrawalCredentials, 256, 32),
    (DepositField::Amount, 320, 8),
    (DepositField::Signature, 384, 96),
    (DepositField::Index, 512, 8),
];

/// A field of the deposit event, named in layout errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositField {
    /// 48-byte BLS public key.
    Pubkey,
    /// 32-byte withdrawal credentials.
    WithdrawalCredentials,
    /// 8-byte little-endian Gwei amount.
    Amount,
    /// 96-byte BLS signature.
    Signature,
    /// 8-byte little-endian deposit index.
    Index,
}

impl fmt::Display for DepositField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pubkey => "pubkey",
            Self::WithdrawalCredentials => "withdrawal_credentials",
            Self::Amount => "amount",
            Self::Signature => "signature",
            Self::Index => "index",
        })
    }
}

/// A deposit-contract log whose data is not a canonically encoded `DepositEvent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositLogError {
    /// The data is not exactly the canonical length.
    Length {
        /// Length of the log data.
        got: usize,
    },
    /// A field's offset word is not the canonical offset.
    Offset {
        /// The field whose offset is wrong.
        field: DepositField,
    },
    /// A field's length word is not the field's fixed size.
    Size {
        /// The field whose size is wrong.
        field: DepositField,
    },
}

impl fmt::Display for DepositLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { got } => write!(
                f,
                "deposit log data is {got} bytes, expected {DEPOSIT_LOG_DATA_LENGTH}"
            ),
            Self::Offset { field } => {
                write!(f, "deposit log field `{field}` has a non-canonical offset")
            }
            Self::Size { field } => {
                write!(f, "deposit log field `{field}` has a non-canonical size")
            }
        }
    }
}

impl core::error::Error for DepositLogError {}

/// Whether `log` is a `DepositEvent` of the deposit contract at `deposit_contract`.
fn is_deposit_event(log: &Log, deposit_contract: H160) -> bool {
    log.address == deposit_contract && log.topics.first() == Some(&DEPOSIT_EVENT_SIGNATURE_HASH)
}

/// Reads the 32-byte big-endian word at `position` as a `usize`, `None` if it does not fit.
fn word(data: &[u8], position: usize) -> Option<usize> {
    let word = data.get(position..position + 32)?;
    let (high, low) = word.split_at(32 - size_of::<usize>());
    if high.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(usize::from_be_bytes(low.try_into().ok()?))
}

/// Appends the five raw fields of one canonically encoded deposit event to `out`.
///
/// # Errors
/// [`DepositLogError`] if the data deviates from the canonical layout in length, any offset or
/// any field size.
pub fn accumulate_deposit_from_log(data: &[u8], out: &mut Vec<u8>) -> Result<(), DepositLogError> {
    if data.len() != DEPOSIT_LOG_DATA_LENGTH {
        return Err(DepositLogError::Length { got: data.len() });
    }
    for (slot, (field, offset, size)) in FIELDS.iter().enumerate() {
        if word(data, slot * 32) != Some(*offset) {
            return Err(DepositLogError::Offset { field: *field });
        }
        if word(data, *offset) != Some(*size) {
            return Err(DepositLogError::Size { field: *field });
        }
    }
    out.reserve(DEPOSIT_REQUEST_LENGTH);
    for (_, offset, size) in FIELDS {
        let start = offset + 32;
        out.extend_from_slice(&data[start..start + size]);
    }
    Ok(())
}

/// Concatenates the deposit requests found in `receipts`, in log order.
///
/// Only logs emitted by `deposit_contract` with the `DepositEvent` topic are considered.
///
/// # Errors
/// [`DepositLogError`] if such a log is not a canonically encoded deposit event.
pub fn parse_deposits_from_receipts(
    receipts: &[Receipt],
    deposit_contract: H160,
) -> Result<Vec<u8>, DepositLogError> {
    let mut out = Vec::new();
    for log in receipts
        .iter()
        .flat_map(|receipt| receipt.logs.iter())
        .filter(|log| is_deposit_event(log, deposit_contract))
    {
        accumulate_deposit_from_log(&log.data, &mut out)?;
    }
    Ok(out)
}
