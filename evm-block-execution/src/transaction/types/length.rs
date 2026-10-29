//! Allocation-free EIP-2718 length calculation for the pre-hashing block-size check.
//!
//! Fixed scalar groups use bounded arithmetic. Aggregate lengths are checked; failures identify
//! the transaction component whose length cannot fit `usize`. List components are evaluated
//! sequentially, stopping at the first component error or overflowing sum.

use super::{
    SignedTxEip1559, SignedTxEip2930, SignedTxEip4844, SignedTxEip7702, SignedTxEnvelope,
    SignedTxLegacy,
};
use crate::rlp_strict::{bytes_length, integer_length, list_length};
use crate::transaction::{AccessList, SignedAuthorization, TxKind, TxSignature};
use primitive_types::U256;

/// Encoded width of an address, including its RLP string prefix.
const ADDRESS_LENGTH: usize = 21;
/// Encoded width of a storage key or blob hash, including its RLP string prefix.
const HASH_LENGTH: usize = 33;

impl SignedTxEnvelope {
    /// Computes the consensus envelope length without encoding or scanning payload bytes.
    ///
    /// # Errors
    /// Returns the first failing field sum or list component; the envelope is checked last.
    /// Component errors are preserved; overflow while summing payload fields returns
    /// [`TxLengthError::Payload`].
    pub(crate) fn encoded_2718_length(&self) -> Result<usize, TxLengthError> {
        let payload = match self {
            Self::Legacy(signed) => legacy_payload_length(signed),
            Self::Eip2930(signed) => eip2930_payload_length(signed),
            Self::Eip1559(signed) => eip1559_payload_length(signed),
            Self::Eip4844(signed) => eip4844_payload_length(signed),
            Self::Eip7702(signed) => eip7702_payload_length(signed),
        }?;
        envelope_length(payload, !matches!(self, Self::Legacy(_)))
    }
}

/// Length of the signed legacy fields, excluding the outer RLP list prefix.
fn legacy_payload_length(signed: &SignedTxLegacy) -> Result<usize, TxLengthError> {
    let tx = &signed.tx;
    add_payload_length(
        base_length(tx.nonce, tx.gas_limit, tx.to, tx.value, &tx.data),
        integer_length(tx.gas_price)
            + integer_length(signed.v().into())
            + signature_scalars_length(&signed.signature),
    )
}

/// Length of the EIP-2930 fields, excluding the envelope prefix and type byte.
fn eip2930_payload_length(signed: &SignedTxEip2930) -> Result<usize, TxLengthError> {
    let tx = &signed.tx;
    let payload = add_payload_length(
        base_length(tx.nonce, tx.gas_limit, tx.to, tx.value, &tx.data),
        integer_length(tx.chain_id.into())
            + integer_length(tx.gas_price)
            + typed_signature_length(&signed.signature),
    )?;
    add_payload_length(payload, access_list_length(&tx.access_list)?)
}

/// Length of the EIP-1559 fields, excluding the envelope prefix and type byte.
fn eip1559_payload_length(signed: &SignedTxEip1559) -> Result<usize, TxLengthError> {
    let tx = &signed.tx;
    let payload = add_payload_length(
        base_length(tx.nonce, tx.gas_limit, tx.to, tx.value, &tx.data),
        dynamic_fee_fields_length(
            tx.chain_id,
            tx.max_priority_fee_per_gas,
            tx.max_fee_per_gas,
            &signed.signature,
        ),
    )?;
    add_payload_length(payload, access_list_length(&tx.access_list)?)
}

/// Length of the EIP-4844 fields, excluding the envelope prefix and type byte.
fn eip4844_payload_length(signed: &SignedTxEip4844) -> Result<usize, TxLengthError> {
    let tx = &signed.tx;
    let payload = add_payload_length(
        base_length(tx.nonce, tx.gas_limit, tx.to, tx.value, &tx.data),
        dynamic_fee_fields_length(
            tx.chain_id,
            tx.max_priority_fee_per_gas,
            tx.max_fee_per_gas,
            &signed.signature,
        ) + integer_length(tx.max_fee_per_blob_gas.into()),
    )?;
    let payload = add_payload_length(payload, access_list_length(&tx.access_list)?)?;
    add_payload_length(payload, blob_hashes_length(tx.blob_versioned_hashes.len())?)
}

/// Length of the EIP-7702 fields, excluding the envelope prefix and type byte.
fn eip7702_payload_length(signed: &SignedTxEip7702) -> Result<usize, TxLengthError> {
    let tx = &signed.tx;
    let payload = add_payload_length(
        base_length(tx.nonce, tx.gas_limit, tx.to, tx.value, &tx.data),
        dynamic_fee_fields_length(
            tx.chain_id,
            tx.max_priority_fee_per_gas,
            tx.max_fee_per_gas,
            &signed.signature,
        ),
    )?;
    let payload = add_payload_length(payload, access_list_length(&tx.access_list)?)?;
    add_payload_length(payload, authorization_list_length(&tx.authorization_list)?)
}

/// Length of a destination, preserving the distinction between a call and creation.
fn destination_length(to: impl Into<TxKind>) -> usize {
    if to.into().is_create() {
        1
    } else {
        ADDRESS_LENGTH
    }
}

/// Length of the common scalar fields and the single data slice.
fn base_length(
    nonce: U256,
    gas_limit: u64,
    to: impl Into<TxKind>,
    value: U256,
    data: &[u8],
) -> usize {
    let fixed = integer_length(nonce)
        + integer_length(gas_limit.into())
        + destination_length(to)
        + integer_length(value);
    // The byte slice is bounded by isize::MAX; its prefix and fixed fields fit usize.
    fixed + bytes_length(data)
}

/// Length of the signature's r and s scalars, excluding legacy v or typed parity.
fn signature_scalars_length(signature: &TxSignature) -> usize {
    integer_length(signature.r) + integer_length(signature.s)
}

/// Length of the typed transaction's one-byte parity and signature scalars.
fn typed_signature_length(signature: &TxSignature) -> usize {
    1 + signature_scalars_length(signature)
}

/// Length of the chain ID, dynamic gas fees and typed signature.
fn dynamic_fee_fields_length(
    chain_id: u64,
    priority: U256,
    max_fee: U256,
    signature: &TxSignature,
) -> usize {
    integer_length(chain_id.into())
        + integer_length(priority)
        + integer_length(max_fee)
        + typed_signature_length(signature)
}

/// Length of the EIP-4844 blob hash list, including its RLP list prefix.
fn blob_hashes_length(count: usize) -> Result<usize, TxLengthError> {
    hash_list_length(count).ok_or(TxLengthError::BlobHashes)
}

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

/// Adds one encoded field group to the payload, checking the aggregate length.
fn add_payload_length(total: usize, length: usize) -> Result<usize, TxLengthError> {
    total.checked_add(length).ok_or(TxLengthError::Payload)
}

/// Adds the outer RLP list prefix and, for typed transactions, the EIP-2718 type byte.
fn envelope_length(payload: usize, typed: bool) -> Result<usize, TxLengthError> {
    list_length(payload)
        .and_then(|length| length.checked_add(usize::from(typed)))
        .ok_or(TxLengthError::Envelope)
}

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

#[cfg(test)]
mod tests {
    use super::{
        SignedTxEnvelope, TxLengthError, access_list_length, add_payload_length,
        authorization_list_length, blob_hashes_length, envelope_length,
    };
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
    fn payload_addition_checks_boundaries() {
        assert_eq!(add_payload_length(usize::MAX - 1, 1), Ok(usize::MAX));
        assert_eq!(add_payload_length(usize::MAX, 0), Ok(usize::MAX));
        assert_eq!(
            add_payload_length(usize::MAX, 1),
            Err(TxLengthError::Payload),
        );
    }

    /// Checks blob-list multiplication and both envelope additions without allocating large values.
    #[test]
    fn blob_hash_and_envelope_overflows_keep_their_categories() {
        assert_eq!(blob_hashes_length(0), Ok(1));
        assert_eq!(blob_hashes_length(1), Ok(34));
        assert_eq!(
            blob_hashes_length(usize::MAX),
            Err(TxLengthError::BlobHashes)
        );

        // These synthetic lengths test arithmetic only; they do not represent allocated slices.
        // The long-list header is one tag byte plus the target pointer width (5 bytes on RV32).
        let header = 1 + core::mem::size_of::<usize>();
        let largest_legacy_payload = usize::MAX - header;
        assert_eq!(
            envelope_length(largest_legacy_payload, false),
            Ok(usize::MAX)
        );
        assert_eq!(
            envelope_length(largest_legacy_payload - 1, true),
            Ok(usize::MAX)
        );
        assert_eq!(
            envelope_length(largest_legacy_payload, true),
            Err(TxLengthError::Envelope),
        );
        assert_eq!(
            envelope_length(usize::MAX, false),
            Err(TxLengthError::Envelope)
        );
    }

    #[test]
    fn envelope_lengths_match_rlp_prefix_boundaries() {
        for payload in [0, 1, 55, 56, 255, 256, 65_535, 65_536] {
            // Each encoded zero occupies one byte, so this list has exactly `payload` payload bytes.
            let mut stream = rlp::RlpStream::new_list(payload);
            for _ in 0..payload {
                stream.append(&0_u8);
            }
            let encoded = stream.out();
            assert_eq!(envelope_length(payload, false), Ok(encoded.len()));
            assert_eq!(envelope_length(payload, true), Ok(encoded.len() + 1));
        }
    }

    #[test]
    fn access_and_blob_lists_match_rlp_at_nested_boundaries() {
        for keys in [0, 1, 2, 7, 8, 17] {
            let hashes = vec![H256::zero(); keys];
            assert_eq!(
                blob_hashes_length(keys),
                Ok(rlp::encode_list(&hashes).len()),
            );
            for items in [0, 1, 2, 3, 10, 11, 12] {
                let list = AccessList(
                    (0..items)
                        .map(|index| AccessListItem {
                            address: H160::zero(),
                            // Mix empty and nonempty key lists instead of repeating equal items.
                            storage_keys: vec![H256::zero(); if index % 2 == 0 { keys } else { 0 }],
                        })
                        .collect(),
                );
                let mut stream = rlp::RlpStream::new();
                super::super::codec::append_access_list(&mut stream, &list);
                assert_eq!(access_list_length(&list), Ok(stream.out().len()));
            }
        }
    }

    #[test]
    fn authorization_lengths_match_rlp_for_empty_lists_and_raw_parity() {
        for parity in [0, 1, 127, 128, 255] {
            for count in [0, 1, 2, 9, 10, 17] {
                let list: Vec<_> = (0..count)
                    .map(|index| SignedAuthorization {
                        chain_id: if index % 2 == 0 {
                            U256::zero()
                        } else {
                            U256::MAX
                        },
                        address: H160::zero(),
                        nonce: if index % 2 == 0 { 127 } else { u64::MAX },
                        y_parity: parity,
                        r: U256::zero(),
                        s: U256::MAX,
                    })
                    .collect();
                assert_eq!(
                    authorization_list_length(&list),
                    Ok(rlp::encode_list(&list).len()),
                );
            }
        }
    }

    #[test]
    fn legacy_lengths_cover_v_boundaries_and_destinations() {
        for (_, raw) in super::super::envelope::tests::vectors() {
            let SignedTxEnvelope::Legacy(mut signed) = SignedTxEnvelope::decode_2718(&raw).unwrap()
            else {
                continue;
            };
            // Parity crosses v=127/128 at chain 46 and v=255/256 at chain 110.
            for chain_id in [None, Some(0), Some(46), Some(110), Some(u64::MAX)] {
                for parity in [false, true] {
                    for to in [TxKind::Create, TxKind::Call(H160::zero())] {
                        signed.tx.chain_id = chain_id;
                        signed.tx.to = to;
                        signed.signature.y_parity = parity;
                        assert_eq!(
                            super::legacy_payload_length(&signed)
                                .and_then(|payload| envelope_length(payload, false)),
                            Ok(rlp::encode(&signed).len()),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn dynamic_fee_lengths_count_each_fee_independently() {
        for (_, raw) in super::super::envelope::tests::vectors() {
            for (priority, max_fee) in [
                (U256::zero(), U256::MAX),
                (U256::MAX, U256::zero()),
                (127.into(), 128.into()),
                (128.into(), 127.into()),
            ] {
                let mut tx = SignedTxEnvelope::decode_2718(&raw).unwrap();
                let (priority_field, max_fee_field) = match &mut tx {
                    SignedTxEnvelope::Eip1559(signed) => (
                        &mut signed.tx.max_priority_fee_per_gas,
                        &mut signed.tx.max_fee_per_gas,
                    ),
                    SignedTxEnvelope::Eip4844(signed) => (
                        &mut signed.tx.max_priority_fee_per_gas,
                        &mut signed.tx.max_fee_per_gas,
                    ),
                    SignedTxEnvelope::Eip7702(signed) => (
                        &mut signed.tx.max_priority_fee_per_gas,
                        &mut signed.tx.max_fee_per_gas,
                    ),
                    SignedTxEnvelope::Legacy(_) | SignedTxEnvelope::Eip2930(_) => continue,
                };
                *priority_field = priority;
                *max_fee_field = max_fee;
                check(&tx);
            }
        }
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
