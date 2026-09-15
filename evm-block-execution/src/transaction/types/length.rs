//! Allocation-free EIP-2718 length calculation for the pre-hashing block-size check.
//!
//! Fixed scalar groups use bounded arithmetic. Aggregate lengths are checked; failures identify
//! the transaction component whose length cannot fit `usize`.

use super::{
    SignedTxEip1559, SignedTxEip4844, SignedTxEip7702, SignedTxEnvelope, TxEip1559, TxEip2930,
    TxEip4844, TxEip7702, TxLegacy,
};
use crate::rlp_strict::{bytes_length, integer_length, list_length};
use crate::transaction::{AccessList, SignedAuthorization, TxKind, TxSignature};

/// The transaction component whose encoded length cannot fit `usize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxLengthError {
    /// The access list, including nested storage-key lists.
    AccessList,
    /// The EIP-7702 authorization list.
    AuthorizationList,
    /// The EIP-4844 blob hash list.
    BlobHashes,
    /// The sum of the transaction's encoded fields.
    Payload,
    /// The payload with its list prefix and optional EIP-2718 type byte.
    Envelope,
}

impl core::fmt::Display for TxLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let component = match self {
            Self::AccessList => "access list",
            Self::AuthorizationList => "authorization list",
            Self::BlobHashes => "blob hash list",
            Self::Payload => "transaction payload",
            Self::Envelope => "transaction envelope",
        };
        write!(f, "{component} encoded length exceeds usize")
    }
}

impl core::error::Error for TxLengthError {}

impl SignedTxEnvelope {
    /// Computes the consensus envelope length without encoding or scanning payload bytes.
    ///
    /// # Errors
    /// Returns the component whose encoded length cannot fit `usize`.
    pub(crate) fn encoded_2718_length(&self) -> Result<usize, TxLengthError> {
        let payload = match self {
            Self::Legacy(signed) => {
                let tx = &signed.tx;
                payload_length(
                    tx.base_length(),
                    integer_length(tx.gas_price)
                        + integer_length(signed.v().into())
                        + signature_scalars_length(&signed.signature),
                    [],
                )
            }
            Self::Eip2930(signed) => {
                let tx = &signed.tx;
                payload_length(
                    tx.base_length(),
                    integer_length(tx.chain_id.into())
                        + integer_length(tx.gas_price)
                        + typed_signature_length(&signed.signature),
                    [access_list_length(&tx.access_list)],
                )
            }
            Self::Eip1559(signed) => {
                let tx = &signed.tx;
                payload_length(
                    tx.base_length(),
                    signed.dynamic_fee_fields_length(),
                    [access_list_length(&tx.access_list)],
                )
            }
            Self::Eip4844(signed) => {
                let tx = &signed.tx;
                payload_length(
                    tx.base_length(),
                    signed.dynamic_fee_fields_length()
                        + integer_length(tx.max_fee_per_blob_gas.into()),
                    [
                        access_list_length(&tx.access_list),
                        hash_list_length(tx.blob_versioned_hashes.len())
                            .ok_or(TxLengthError::BlobHashes),
                    ],
                )
            }
            Self::Eip7702(signed) => {
                let tx = &signed.tx;
                payload_length(
                    tx.base_length(),
                    signed.dynamic_fee_fields_length(),
                    [
                        access_list_length(&tx.access_list),
                        authorization_list_length(&tx.authorization_list),
                    ],
                )
            }
        }?;
        list_length(payload)
            .and_then(|length| length.checked_add(usize::from(!matches!(self, Self::Legacy(_)))))
            .ok_or(TxLengthError::Envelope)
    }
}

/// Encoded width of an address, including its RLP string prefix.
const ADDRESS_LENGTH: usize = 21;
/// Encoded width of a storage key or blob hash, including its RLP string prefix.
const HASH_LENGTH: usize = 33;

/// Length of a destination, preserving the distinction between a call and creation.
fn destination_length(to: impl Into<TxKind>) -> usize {
    if to.into().is_create() {
        1
    } else {
        ADDRESS_LENGTH
    }
}

// These concrete types share fields but no common transaction trait.
macro_rules! impl_base_length {
    ($($ty:ty),+ $(,)?) => {
        $(impl $ty {
            /// Length of the common scalar fields and the single data slice.
            fn base_length(&self) -> usize {
                let fixed = integer_length(self.nonce)
                    + integer_length(self.gas_limit.into())
                    + destination_length(self.to)
                    + integer_length(self.value);
                // The byte slice is bounded by isize::MAX; its prefix and fixed fields fit usize.
                fixed + bytes_length(&self.data)
            }
        })+
    };
}

impl_base_length!(TxLegacy, TxEip2930, TxEip1559, TxEip4844, TxEip7702);

/// Length of the signature's r and s scalars, excluding legacy v or typed parity.
fn signature_scalars_length(signature: &TxSignature) -> usize {
    integer_length(signature.r) + integer_length(signature.s)
}

/// Length of the typed transaction's one-byte parity and signature scalars.
fn typed_signature_length(signature: &TxSignature) -> usize {
    1 + signature_scalars_length(signature)
}

// Generate only the fields shared by the three signed dynamic-fee formats.
macro_rules! impl_dynamic_fee_fields_length {
    ($($ty:ty),+ $(,)?) => {
        $(impl $ty {
            /// Length of the chain ID, dynamic gas fees and typed signature.
            fn dynamic_fee_fields_length(&self) -> usize {
                integer_length(self.tx.chain_id.into())
                    + integer_length(self.tx.max_priority_fee_per_gas)
                    + integer_length(self.tx.max_fee_per_gas)
                    + typed_signature_length(&self.signature)
            }
        })+
    };
}

impl_dynamic_fee_fields_length!(SignedTxEip1559, SignedTxEip4844, SignedTxEip7702);

/// Length of a list of fixed-width storage keys or blob hashes.
fn hash_list_length(count: usize) -> Option<usize> {
    count.checked_mul(HASH_LENGTH).and_then(list_length)
}

/// Length of the access list and its nested storage-key lists.
fn access_list_length(list: &AccessList) -> Result<usize, TxLengthError> {
    let payload = list.iter().try_fold(0_usize, |total, item| {
        let keys = hash_list_length(item.storage_keys.len())?;
        let item = list_length(ADDRESS_LENGTH.checked_add(keys)?)?;
        total.checked_add(item)
    });
    payload
        .and_then(list_length)
        .ok_or(TxLengthError::AccessList)
}

/// Length of the EIP-7702 authorization list; its parity is measured as an unvalidated u8.
fn authorization_list_length(list: &[SignedAuthorization]) -> Result<usize, TxLengthError> {
    let payload = list.iter().try_fold(0_usize, |total, auth| {
        let fields = integer_length(auth.chain_id)
            + ADDRESS_LENGTH
            + integer_length(auth.nonce.into())
            + integer_length(auth.y_parity.into())
            + integer_length(auth.r)
            + integer_length(auth.s);
        total.checked_add(list_length(fields)?)
    });
    payload
        .and_then(list_length)
        .ok_or(TxLengthError::AuthorizationList)
}

/// Adds bounded fields and encoded lists, preserving the first failing component or sum.
fn payload_length(
    base: usize,
    fixed: usize,
    lists: impl IntoIterator<Item = Result<usize, TxLengthError>>,
) -> Result<usize, TxLengthError> {
    let initial = base.checked_add(fixed).ok_or(TxLengthError::Payload)?;
    lists.into_iter().try_fold(initial, |total, length| {
        total.checked_add(length?).ok_or(TxLengthError::Payload)
    })
}

#[cfg(test)]
mod tests {
    use super::{SignedTxEnvelope, TxLengthError, payload_length};
    use crate::transaction::{AccessList, AccessListItem, SignedAuthorization, TxKind};
    use primitive_types::{H160, H256, U256};

    fn check(tx: &SignedTxEnvelope) {
        assert_eq!(
            tx.encoded_2718_length(),
            Ok(tx.encoded_2718().len()),
            "{:?}",
            tx.tx_type()
        );
    }

    #[test]
    fn payload_lengths_preserve_boundaries_and_error_priority() {
        assert_eq!(payload_length(usize::MAX - 2, 1, [Ok(1)]), Ok(usize::MAX));
        assert_eq!(
            payload_length(usize::MAX - 2, 1, [Ok(2)]),
            Err(TxLengthError::Payload),
        );
        // A failed sum precedes errors in subsequent components.
        assert_eq!(
            payload_length(usize::MAX, 1, [Err(TxLengthError::AccessList)]),
            Err(TxLengthError::Payload),
        );
        assert_eq!(
            payload_length(
                0,
                0,
                [Ok(usize::MAX), Ok(1), Err(TxLengthError::BlobHashes)]
            ),
            Err(TxLengthError::Payload),
        );
        // Otherwise preserve the first component error rather than reclassifying it as a sum.
        assert_eq!(
            payload_length(
                0,
                0,
                [
                    Err(TxLengthError::AccessList),
                    Err(TxLengthError::AuthorizationList)
                ]
            ),
            Err(TxLengthError::AccessList),
        );
    }

    #[test]
    fn lengths_match_pinned_eest_transaction_bytes() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../../../testdata/ordered-roots.json")).unwrap();
        let mut count = 0;
        for case in cases.as_array().unwrap() {
            if case["kind"] != "transactions" {
                continue;
            }
            for value in case["values"].as_array().unwrap() {
                let raw = hex::decode(value.as_str().unwrap()).unwrap();
                let tx = SignedTxEnvelope::decode_2718(&raw).unwrap();
                assert_eq!(
                    tx.encoded_2718_length(),
                    Ok(raw.len()),
                    "{}",
                    case["source"]
                );
                count += 1;
            }
        }
        assert!(count >= 128);
    }

    #[test]
    fn lengths_cover_all_types_scalars_and_nested_lists() {
        for (_, raw) in super::super::envelope::tests::vectors() {
            for scalar in [
                U256::zero(),
                1.into(),
                127.into(),
                128.into(),
                255.into(),
                256.into(),
                U256::MAX,
            ] {
                for data in [
                    vec![],
                    vec![0],
                    vec![0x7f],
                    vec![0x80],
                    vec![0xff],
                    vec![7; 55],
                    vec![7; 56],
                    vec![7; 256],
                ] {
                    let mut tx = SignedTxEnvelope::decode_2718(&raw).unwrap();
                    let access = AccessList(vec![
                        AccessListItem {
                            address: H160::zero(),
                            storage_keys: vec![H256::zero(); 2]
                        };
                        17
                    ]);
                    macro_rules! common {
                        ($signed:ident) => {
                            $signed.tx.nonce = scalar;
                            $signed.tx.gas_limit = u64::MAX;
                            $signed.tx.value = scalar;
                            $signed.tx.data = data;
                            $signed.signature.r = scalar;
                            $signed.signature.s = scalar;
                        };
                    }
                    macro_rules! dynamic {
                        ($signed:ident) => {
                            common!($signed);
                            $signed.tx.chain_id = u64::MAX;
                            $signed.tx.max_fee_per_gas = scalar;
                            $signed.tx.max_priority_fee_per_gas = scalar;
                            $signed.tx.access_list = access;
                        };
                    }
                    match &mut tx {
                        SignedTxEnvelope::Legacy(signed) => {
                            common!(signed);
                            signed.tx.chain_id = Some(u64::MAX);
                            signed.tx.to = TxKind::Create;
                            signed.tx.gas_price = scalar;
                        }
                        SignedTxEnvelope::Eip2930(signed) => {
                            common!(signed);
                            signed.tx.chain_id = u64::MAX;
                            signed.tx.gas_price = scalar;
                            signed.tx.to = TxKind::Create;
                            signed.tx.access_list = access;
                        }
                        SignedTxEnvelope::Eip1559(signed) => {
                            dynamic!(signed);
                            signed.tx.to = TxKind::Create;
                        }
                        SignedTxEnvelope::Eip4844(signed) => {
                            dynamic!(signed);
                            signed.tx.max_fee_per_blob_gas = u128::MAX;
                            signed.tx.blob_versioned_hashes = vec![H256::zero(); 17];
                        }
                        SignedTxEnvelope::Eip7702(signed) => {
                            dynamic!(signed);
                            signed.tx.authorization_list = vec![
                                SignedAuthorization {
                                    chain_id: scalar,
                                    address: H160::zero(),
                                    nonce: u64::MAX,
                                    y_parity: 255,
                                    r: scalar,
                                    s: scalar,
                                };
                                17
                            ];
                        }
                    }
                    check(&tx);
                }
            }
        }
    }
}
