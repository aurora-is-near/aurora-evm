//! [EIP-2930] access-list transaction, type byte `0x01`.
//!
//! [EIP-2930]: https://eips.ethereum.org/EIPS/eip-2930

use super::codec::{
    TxDecodeError, append_access_list, append_destination, append_signature, decode_access_list,
    decode_destination, decode_signature, expect_items,
};
use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, TxKind, TxType};
use primitive_types::{H160, U256};

/// The EIP-2930 type byte.
pub const TYPE_BYTE: u8 = 0x01;
const TRANSACTION_FIELDS: usize = 8;
const SIGNATURE_FIELDS: usize = 3;
const SIGNED_TRANSACTION_FIELDS: usize = TRANSACTION_FIELDS + SIGNATURE_FIELDS;
const SIGNATURE_INDEX: usize = TRANSACTION_FIELDS;
const ACCESS_LIST_INDEX: usize = 7;

/// A normalized EIP-2930 transaction: legacy fields with a chain id and access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEip2930 {
    /// Chain this transaction is valid on. Mandatory from this type onward.
    pub chain_id: u64,
    /// Sender's transaction counter.
    pub nonce: U256,
    /// Price per gas unit.
    pub gas_price: U256,
    /// Maximum gas the transaction may consume.
    pub gas_limit: u64,
    /// Destination, or a contract creation.
    pub to: TxKind,
    /// Value transferred.
    pub value: U256,
    /// Call data, or init code for a creation.
    pub data: Vec<u8>,
    /// Addresses and storage slots pre-warmed for this transaction.
    pub access_list: AccessList,
}

impl TxEip2930 {
    /// Appends the fields shared by the signed and signing encodings.
    fn append_fields(&self, stream: &mut rlp::RlpStream) {
        stream.append(&self.chain_id);
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas_limit);
        append_destination(stream, self.to);
        stream.append(&self.value);
        stream.append(&self.data);
        append_access_list(stream, &self.access_list);
    }

    /// Encodes this transaction for signing into `stream`, clearing it first.
    pub(crate) fn encode_for_signing_in(&self, stream: &mut rlp::RlpStream) {
        stream.clear();
        stream.append_raw(&[TYPE_BYTE], 0);
        stream.begin_list(TRANSACTION_FIELDS);
        self.append_fields(stream);
    }

    /// Converts into the execution environment for `caller`, moving owned data.
    /// Named destructuring makes new consensus fields compile-time update points.
    #[must_use]
    pub fn into_tx_env(self, caller: H160) -> TxEnv {
        let Self {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            access_list,
        } = self;

        TxEnv {
            tx_type: TxType::Eip2930,
            caller,
            tx_kind: to,
            gas_limit,
            value,
            data,
            nonce,
            chain_id: Some(chain_id),
            gas_price: Some(gas_price),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list,
            blob_versioned_hashes: Vec::new(),
            max_fee_per_blob_gas: 0,
            authorization_list: Vec::new(),
        }
    }
}

/// A signed EIP-2930 transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxEip2930 {
    /// The signed fields.
    pub tx: TxEip2930,
    /// The sender's signature.
    pub signature: TxSignature,
}

impl SignedTxEip2930 {
    /// Decodes the signed field list that follows the type byte.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the list has the wrong shape, `to` is malformed, or
    /// `y_parity` is not 0 or 1.
    pub fn decode_strict(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, SIGNED_TRANSACTION_FIELDS)?;
        Ok(Self {
            tx: TxEip2930 {
                chain_id: rlp.val_at(0)?,
                nonce: rlp.val_at(1)?,
                gas_price: rlp.val_at(2)?,
                gas_limit: rlp.val_at(3)?,
                to: decode_destination(rlp, 4)?,
                value: rlp.val_at(5)?,
                data: rlp.val_at(6)?,
                access_list: decode_access_list(rlp, ACCESS_LIST_INDEX)?,
            },
            signature: decode_signature(rlp, SIGNATURE_INDEX)?,
        })
    }
}

impl rlp::Encodable for SignedTxEip2930 {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(SIGNED_TRANSACTION_FIELDS);
        self.tx.append_fields(stream);
        append_signature(stream, &self.signature);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACCESS_LIST_INDEX, SIGNED_TRANSACTION_FIELDS, SignedTxEip2930, TRANSACTION_FIELDS,
        TYPE_BYTE, TxEip2930,
    };
    use crate::transaction::TxEnv;
    use crate::transaction::TxType;
    use hex_literal::hex;
    use primitive_types::H160;

    /// A real EIP-2930 transaction with a non-empty access list.
    const RAW: &[u8] = &hex!(
        "01f89b01800a8301e974943068947c19dbbc5a170610a69c65e341f0a0b7458080f838f7940000000000000000000000000000000000000000e1a0000000000000000000000000000000000000000000000000000000000000000001a0712d63f4983ce033255f9adfe3b159f465766eac906591091e3ad03ffc06ad16a0078e21a3501b9fc9b9b9e223cc19768be044d5c7c6faf1fbc0f5aa4deb325fe9"
    );

    fn decoded() -> SignedTxEip2930 {
        SignedTxEip2930::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap()
    }

    fn encoded_for_signing(tx: &TxEip2930) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        tx.encode_for_signing_in(&mut stream);
        stream.out().to_vec()
    }

    #[test]
    fn the_encoding_for_signing_omits_the_signature() {
        let typed = decoded();
        let encoded = encoded_for_signing(&typed.tx);
        assert_eq!(encoded[0], TYPE_BYTE);
        assert_eq!(
            rlp::Rlp::new(&encoded[1..]).item_count().unwrap(),
            TRANSACTION_FIELDS
        );
    }

    #[test]
    fn a_byte_string_where_the_access_list_belongs_is_rejected() {
        let rlp = rlp::Rlp::new(&RAW[1..]);
        let mut stream = rlp::RlpStream::new_list(SIGNED_TRANSACTION_FIELDS);
        for i in 0..SIGNED_TRANSACTION_FIELDS {
            if i == ACCESS_LIST_INDEX {
                stream.append(&vec![0xaau8; 3]);
            } else {
                stream.append_raw(rlp.at(i).unwrap().as_raw(), 1);
            }
        }
        assert!(SignedTxEip2930::decode_strict(&rlp::Rlp::new(&stream.out())).is_err());
    }

    /// Projection preserves this type's fields and canonical absences for unsupported fields.
    #[test]
    fn the_projection_carries_its_own_fields_and_nothing_else() {
        let typed = decoded();
        let TxEnv {
            tx_type,
            caller,
            tx_kind,
            gas_limit,
            value,
            data,
            nonce,
            chain_id,
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list,
            blob_versioned_hashes,
            max_fee_per_blob_gas,
            authorization_list,
        } = typed.tx.clone().into_tx_env(H160::zero());

        assert_eq!(tx_type, TxType::Eip2930);
        assert_eq!(tx_kind, typed.tx.to);
        assert_eq!(gas_limit, typed.tx.gas_limit);
        assert_eq!(value, typed.tx.value);
        assert_eq!(data, typed.tx.data);
        assert_eq!(nonce, typed.tx.nonce);
        assert_eq!(chain_id, Some(typed.tx.chain_id));
        assert_eq!(gas_price, Some(typed.tx.gas_price));
        assert_eq!(access_list, typed.tx.access_list);
        // A 2930 transaction has no dynamic fees, and the projection says so rather than inventing
        // a value no signature covered.
        assert_eq!(max_fee_per_gas, None);
        assert_eq!(max_priority_fee_per_gas, None);
        assert!(blob_versioned_hashes.is_empty());
        assert_eq!(max_fee_per_blob_gas, 0);
        assert_eq!(caller, H160::zero());
        assert!(authorization_list.is_empty());
    }
}
