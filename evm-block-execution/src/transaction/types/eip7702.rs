//! [EIP-7702] set-code transaction, type byte `0x04`.
//!
//! [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702

use super::codec::{
    TxDecodeError, append_access_list, append_signature, decode_access_list,
    decode_required_destination, decode_signature, expect_items,
};
use crate::rlp_strict;
use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, SignedAuthorization, TxKind, TxType};
use aurora_evm::executor::stack::Authorization;
use primitive_types::{H160, U256};

/// The EIP-7702 type byte.
pub const TYPE_BYTE: u8 = 0x04;
const TRANSACTION_FIELDS: usize = 10;
const SIGNATURE_FIELDS: usize = 3;
const SIGNED_TRANSACTION_FIELDS: usize = TRANSACTION_FIELDS + SIGNATURE_FIELDS;
const SIGNATURE_INDEX: usize = TRANSACTION_FIELDS;
const ACCESS_LIST_INDEX: usize = 8;
const AUTHORIZATION_LIST_INDEX: usize = 9;

/// A normalized EIP-7702 set-code transaction.
///
/// Its `H160` destination makes contract creation unrepresentable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEip7702 {
    /// Chain this transaction is valid on.
    pub chain_id: u64,
    /// Sender's transaction counter.
    pub nonce: U256,
    /// Tip paid to the block's beneficiary, on top of the base fee.
    pub max_priority_fee_per_gas: U256,
    /// Total the sender will pay per gas unit, base fee included.
    pub max_fee_per_gas: U256,
    /// Maximum gas the transaction may consume.
    pub gas_limit: u64,
    /// Destination. A set-code transaction cannot be a creation.
    pub to: H160,
    /// Value transferred.
    pub value: U256,
    /// Call data.
    pub data: Vec<u8>,
    /// Addresses and storage slots pre-warmed for this transaction.
    pub access_list: AccessList,
    /// Delegations signed independently by their authorities. Invalid entries are ineffective.
    pub authorization_list: Vec<SignedAuthorization>,
}

impl TxEip7702 {
    /// Appends the fields shared by the signed and signing encodings.
    fn append_fields(&self, stream: &mut rlp::RlpStream) {
        stream.append(&self.chain_id);
        stream.append(&self.nonce);
        stream.append(&self.max_priority_fee_per_gas);
        stream.append(&self.max_fee_per_gas);
        stream.append(&self.gas_limit);
        stream.append(&self.to);
        stream.append(&self.value);
        stream.append(&self.data);
        append_access_list(stream, &self.access_list);
        stream.append_list(&self.authorization_list);
    }

    /// Encodes this transaction for signing into `stream`, clearing it first.
    pub(crate) fn encode_for_signing_in(&self, stream: &mut rlp::RlpStream) {
        stream.clear();
        stream.append_raw(&[TYPE_BYTE], 0);
        stream.begin_list(TRANSACTION_FIELDS);
        self.append_fields(stream);
    }

    /// The authorities this transaction's tuples authorize, one entry per tuple.
    ///
    /// One RLP buffer is reused across tuples. Failed tuples remain as `is_valid: false` because
    /// intrinsic gas is charged per tuple.
    #[must_use]
    pub fn recovered_authorizations(&self) -> Vec<Authorization> {
        let mut stream = rlp::RlpStream::new();
        self.authorization_list
            .iter()
            .map(|tuple| tuple.recover_authority(self.chain_id, &mut stream))
            .collect()
    }

    /// Converts into the execution environment for `caller`, moving owned data.
    /// Named destructuring makes new consensus fields compile-time update points.
    #[must_use]
    pub fn into_tx_env(self, caller: H160) -> TxEnv {
        // Recovery borrows the tuples, so do it before moving the transaction fields.
        let authorization_list = self.recovered_authorizations();

        let Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            authorization_list: _tuples,
        } = self;

        TxEnv {
            tx_type: TxType::Eip7702,
            caller,
            tx_kind: TxKind::Call(to),
            gas_limit,
            value,
            data,
            nonce,
            chain_id: Some(chain_id),
            gas_price: None,
            max_fee_per_gas: Some(max_fee_per_gas),
            max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
            access_list,
            blob_versioned_hashes: Vec::new(),
            max_fee_per_blob_gas: 0,
            authorization_list,
        }
    }
}

/// A signed set-code transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxEip7702 {
    /// The signed fields.
    pub tx: TxEip7702,
    /// The sender's signature. Distinct from the signatures inside `authorization_list`.
    pub signature: TxSignature,
}

impl SignedTxEip7702 {
    /// Decodes the signed field list that follows the type byte.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the list has the wrong shape, the transaction is a
    /// creation, an authorization tuple is malformed, or the transaction sender's `y_parity` is not
    /// 0 or 1. A tuple's own `y_parity` may be any `u8`; values above 1 make that tuple ineffective.
    pub fn decode_strict(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, SIGNED_TRANSACTION_FIELDS)?;
        Ok(Self {
            tx: TxEip7702 {
                chain_id: rlp.val_at(0)?,
                nonce: rlp.val_at(1)?,
                max_priority_fee_per_gas: rlp.val_at(2)?,
                max_fee_per_gas: rlp.val_at(3)?,
                gas_limit: rlp.val_at(4)?,
                to: decode_required_destination(rlp, 5, TxType::Eip7702)?,
                value: rlp.val_at(6)?,
                data: rlp.val_at(7)?,
                access_list: decode_access_list(rlp, ACCESS_LIST_INDEX)?,
                authorization_list: rlp_strict::checked_list_at(rlp, AUTHORIZATION_LIST_INDEX)?,
            },
            signature: decode_signature(rlp, SIGNATURE_INDEX)?,
        })
    }
}

impl rlp::Encodable for SignedTxEip7702 {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(SIGNED_TRANSACTION_FIELDS);
        self.tx.append_fields(stream);
        append_signature(stream, &self.signature);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORIZATION_LIST_INDEX, SignedTxEip7702, TRANSACTION_FIELDS, TYPE_BYTE, TxEip7702,
    };
    use crate::transaction::TxEnv;
    use crate::transaction::{SignedAuthorization, TxKind, TxType};
    use hex_literal::hex;
    use primitive_types::H160;
    use primitive_types::U256;

    /// A real set-code transaction, carrying one authorization.
    const RAW: &[u8] = &hex!(
        "04f8e101808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a00000"
        "00000000000000000000000000000000000000000000000000000000000cc0f85cf85a80"
        "9400000000000000000000000000000000000000008080a085044e88414585239b3b7b4f"
        "91c0bc6275ed817b925d973869370ca9b842925aa02e021ec5210eb0cc051524a05e9049"
        "d6a57acdf0386e3feeae658df6d2a242a980a0f2e0c327202f18c44b074c628433f8d7ed"
        "09f7fbe180684f1ab6da84b8d94c4aa00c755520f565a678bac8959549dba76a7c212002"
        "5b53e1565b09845880a66dbf"
    );

    fn decoded() -> SignedTxEip7702 {
        SignedTxEip7702::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap()
    }

    fn encoded_for_signing(tx: &TxEip7702) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        tx.encode_for_signing_in(&mut stream);
        stream.out().to_vec()
    }

    #[test]
    fn the_encoding_for_signing_omits_the_senders_signature_but_keeps_the_authorizations() {
        let typed = decoded();
        let encoded = encoded_for_signing(&typed.tx);
        assert_eq!(encoded[0], TYPE_BYTE);
        let rlp = rlp::Rlp::new(&encoded[1..]);
        assert_eq!(rlp.item_count().unwrap(), TRANSACTION_FIELDS);
        assert_eq!(
            rlp.at(AUTHORIZATION_LIST_INDEX)
                .unwrap()
                .item_count()
                .unwrap(),
            1
        );
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

        assert_eq!(tx_type, TxType::Eip7702);
        assert_eq!(tx_kind, TxKind::Call(typed.tx.to));
        assert_eq!(gas_limit, typed.tx.gas_limit);
        assert_eq!(value, typed.tx.value);
        assert_eq!(data, typed.tx.data);
        assert_eq!(nonce, typed.tx.nonce);
        assert_eq!(chain_id, Some(typed.tx.chain_id));
        assert_eq!(max_fee_per_gas, Some(typed.tx.max_fee_per_gas));
        assert_eq!(
            max_priority_fee_per_gas,
            Some(typed.tx.max_priority_fee_per_gas)
        );
        assert_eq!(access_list, typed.tx.access_list);
        assert_eq!(gas_price, None);
        assert!(blob_versioned_hashes.is_empty());
        assert_eq!(max_fee_per_blob_gas, 0);
        assert_eq!(caller, H160::zero());
        // The consensus tuples project one-to-one into recovered authorities.
        assert_eq!(
            authorization_list.len(),
            typed.tx.authorization_list.len(),
            "one recovered authority per signed tuple"
        );
        for (recovered, tuple) in authorization_list.iter().zip(&typed.tx.authorization_list) {
            assert_eq!(recovered.address, tuple.address);
            assert_eq!(recovered.nonce, tuple.nonce);
        }
    }

    /// Failed tuples remain in place because intrinsic gas is charged per tuple.
    #[test]
    fn recovery_keeps_one_entry_per_tuple_however_it_fails() {
        let tx = decoded().tx;
        let good = tx.recovered_authorizations();
        assert_eq!(good.len(), tx.authorization_list.len());
        assert!(good[0].is_valid, "the published tuple must recover");
        assert_eq!(
            good[0].authority,
            H160(hex!("dde0a8f1c754bca49c7ad9017cbb242d3116d9a3")),
            "authority independently recovered from the published tuple"
        );

        // Four independent failures plus one valid tuple; every input still yields one entry.
        let mut tx = tx;
        let sound = tx.authorization_list[0];
        let broken = vec![
            sound, // as decoded
            SignedAuthorization {
                y_parity: 27, // not a parity: no signature at all
                ..sound
            },
            SignedAuthorization {
                chain_id: U256::from(u64::MAX), // a chain this transaction is not on
                ..sound
            },
            SignedAuthorization {
                s: crate::transaction::SECP256K1N_HALF + U256::one(), // EIP-2 unnormalized
                ..sound
            },
            SignedAuthorization {
                r: U256::zero(), // no key recovers from this
                s: U256::zero(),
                ..sound
            },
        ];
        let expected = broken.len();
        tx.authorization_list = broken;

        let recovered = tx.recovered_authorizations();
        assert_eq!(recovered.len(), expected, "no tuple may be dropped");
        for (index, entry) in recovered.iter().enumerate() {
            assert_eq!(
                entry.address, sound.address,
                "entry {index} keeps its target"
            );
            assert_eq!(entry.nonce, sound.nonce, "entry {index} keeps its nonce");
            if !entry.is_valid {
                assert_eq!(
                    entry.authority,
                    H160::zero(),
                    "entry {index} authorises nobody, so it names nobody"
                );
            }
        }
        // The last four are broken in four different ways; none of them may be valid.
        assert_eq!(recovered[0], good[0], "the sound tuple must still recover");
        assert!(recovered[1..].iter().all(|entry| !entry.is_valid));
    }

    /// Reusing one RLP buffer must match recovering each tuple independently.
    #[test]
    fn a_shared_rlp_buffer_does_not_leak_between_tuples() {
        let mut tx = decoded().tx;
        let one = tx.authorization_list[0];
        let other = SignedAuthorization { nonce: 9, ..one };
        tx.authorization_list = vec![one, other, one, other];

        let together = tx.recovered_authorizations();

        let mut alone = Vec::new();
        for tuple in [one, other, one, other] {
            let mut single = tx.clone();
            single.authorization_list = vec![tuple];
            alone.extend(single.recovered_authorizations());
        }
        assert_eq!(
            together, alone,
            "a shared buffer must give per-tuple results"
        );
        assert_eq!(together[0], together[2]);
        assert_eq!(together[1], together[3]);
    }
}
