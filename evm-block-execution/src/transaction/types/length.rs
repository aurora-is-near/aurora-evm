//! Allocation-free EIP-2718 length calculation for the pre-hashing block-size check.
//!
//! Fixed scalar groups use bounded arithmetic. Aggregate lengths are checked; failures identify
//! the transaction component whose length cannot fit `usize`.

use super::SignedTxEnvelope;
use crate::rlp_strict::{bytes_length, integer_length, list_length};
use crate::transaction::{AccessList, SignedAuthorization, TxKind, TxSignature};
use primitive_types::U256;

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

/// Length of the typed transaction's parity and signature scalars.
fn signature_length(signature: &TxSignature) -> usize {
    1 + integer_length(signature.r) + integer_length(signature.s)
}

/// Length of the access list and its nested storage-key lists.
fn access_list_length(list: &AccessList) -> Option<usize> {
    let payload = list.iter().try_fold(0_usize, |total, item| {
        let keys = list_length(item.storage_keys.len().checked_mul(33)?)?;
        let item = list_length(21_usize.checked_add(keys)?)?;
        total.checked_add(item)
    })?;
    list_length(payload)
}

/// Length of the EIP-7702 authorization list.
fn authorization_list_length(list: &[SignedAuthorization]) -> Option<usize> {
    let payload = list.iter().try_fold(0_usize, |total, auth| {
        let fields = integer_length(auth.chain_id)
            + 21
            + integer_length(auth.nonce.into())
            + integer_length(auth.y_parity.into())
            + integer_length(auth.r)
            + integer_length(auth.s);
        total.checked_add(list_length(fields)?)
    })?;
    list_length(payload)
}

/// Length of the common scalar fields and the single data slice.
fn base_length(nonce: U256, gas_limit: u64, to: TxKind, value: U256, data: &[u8]) -> usize {
    let fixed = integer_length(nonce)
        + integer_length(gas_limit.into())
        + if to.is_create() { 1 } else { 21 }
        + integer_length(value);
    // The slice is bounded by isize::MAX; fixed fields and its prefix fit usize.
    fixed + bytes_length(data)
}

impl SignedTxEnvelope {
    /// Computes the consensus envelope length without encoding or scanning payload bytes.
    ///
    /// # Errors
    /// Returns the component whose encoded length cannot fit `usize`.
    pub(crate) fn encoded_2718_length(&self) -> Result<usize, TxLengthError> {
        let payload = match self {
            Self::Legacy(signed) => {
                let tx = &signed.tx;
                base_length(tx.nonce, tx.gas_limit, tx.to, tx.value, &tx.data)
                    .checked_add(
                        integer_length(tx.gas_price)
                            + integer_length(signed.v().into())
                            + integer_length(signed.signature.r)
                            + integer_length(signed.signature.s),
                    )
                    .ok_or(TxLengthError::Payload)?
            }
            Self::Eip2930(signed) => {
                let tx = &signed.tx;
                base_length(tx.nonce, tx.gas_limit, tx.to, tx.value, &tx.data)
                    .checked_add(
                        integer_length(tx.chain_id.into())
                            + integer_length(tx.gas_price)
                            + signature_length(&signed.signature),
                    )
                    .ok_or(TxLengthError::Payload)?
                    .checked_add(
                        access_list_length(&tx.access_list).ok_or(TxLengthError::AccessList)?,
                    )
                    .ok_or(TxLengthError::Payload)?
            }
            Self::Eip1559(signed) => {
                let tx = &signed.tx;
                base_length(tx.nonce, tx.gas_limit, tx.to, tx.value, &tx.data)
                    .checked_add(
                        integer_length(tx.chain_id.into())
                            + integer_length(tx.max_priority_fee_per_gas)
                            + integer_length(tx.max_fee_per_gas)
                            + signature_length(&signed.signature),
                    )
                    .ok_or(TxLengthError::Payload)?
                    .checked_add(
                        access_list_length(&tx.access_list).ok_or(TxLengthError::AccessList)?,
                    )
                    .ok_or(TxLengthError::Payload)?
            }
            Self::Eip4844(signed) => {
                let tx = &signed.tx;
                base_length(
                    tx.nonce,
                    tx.gas_limit,
                    TxKind::Call(tx.to),
                    tx.value,
                    &tx.data,
                )
                .checked_add(
                    integer_length(tx.chain_id.into())
                        + integer_length(tx.max_priority_fee_per_gas)
                        + integer_length(tx.max_fee_per_gas)
                        + integer_length(tx.max_fee_per_blob_gas.into())
                        + signature_length(&signed.signature),
                )
                .ok_or(TxLengthError::Payload)?
                .checked_add(access_list_length(&tx.access_list).ok_or(TxLengthError::AccessList)?)
                .ok_or(TxLengthError::Payload)?
                .checked_add(
                    tx.blob_versioned_hashes
                        .len()
                        .checked_mul(33)
                        .and_then(list_length)
                        .ok_or(TxLengthError::BlobHashes)?,
                )
                .ok_or(TxLengthError::Payload)?
            }
            Self::Eip7702(signed) => {
                let tx = &signed.tx;
                base_length(
                    tx.nonce,
                    tx.gas_limit,
                    TxKind::Call(tx.to),
                    tx.value,
                    &tx.data,
                )
                .checked_add(
                    integer_length(tx.chain_id.into())
                        + integer_length(tx.max_priority_fee_per_gas)
                        + integer_length(tx.max_fee_per_gas)
                        + signature_length(&signed.signature),
                )
                .ok_or(TxLengthError::Payload)?
                .checked_add(access_list_length(&tx.access_list).ok_or(TxLengthError::AccessList)?)
                .ok_or(TxLengthError::Payload)?
                .checked_add(
                    authorization_list_length(&tx.authorization_list)
                        .ok_or(TxLengthError::AuthorizationList)?,
                )
                .ok_or(TxLengthError::Payload)?
            }
        };
        list_length(payload)
            .and_then(|length| length.checked_add(usize::from(!matches!(self, Self::Legacy(_)))))
            .ok_or(TxLengthError::Envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::SignedTxEnvelope;
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
