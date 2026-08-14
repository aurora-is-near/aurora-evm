//! [EIP-1559] dynamic-fee transaction, type byte `0x02`.
//!
//! [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559

use super::{
    TxDecodeError, append_access_list, append_destination, append_signature, decode_access_list,
    decode_destination, decode_signature, expect_items,
};
use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, TxKind, TxType};
use primitive_types::{H160, U256};

/// The EIP-1559 type byte.
pub const TYPE_BYTE: u8 = 0x02;

/// An EIP-1559 transaction's own fields: a fee cap and a tip in place of `gas_price`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEip1559 {
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
    /// Destination, or a contract creation.
    pub to: TxKind,
    /// Value transferred.
    pub value: U256,
    /// Call data, or init code for a creation.
    pub data: Vec<u8>,
    /// Addresses and storage slots pre-warmed for this transaction.
    pub access_list: AccessList,
}

impl TxEip1559 {
    /// The nine fields, shared by the signed encoding and the signing preimage.
    fn append_fields(&self, stream: &mut rlp::RlpStream) {
        stream.append(&self.chain_id);
        stream.append(&self.nonce);
        stream.append(&self.max_priority_fee_per_gas);
        stream.append(&self.max_fee_per_gas);
        stream.append(&self.gas_limit);
        append_destination(stream, self.to);
        stream.append(&self.value);
        stream.append(&self.data);
        append_access_list(stream, &self.access_list);
    }

    /// Writes the signing preimage — the type byte, then this type\'s fields — into `stream`.
    ///
    /// The type byte goes in as raw bytes ahead of the list, so the preimage is one contiguous buffer
    /// rather than a list that then has to be copied to make room for a prefix. Takes the stream so a
    /// caller hashing a whole block's transactions can reuse one buffer for all of them.
    ///
    /// The list is unbounded and finalised, so the stream counts the fields itself. A hand-written count
    /// would be the field list repeated in a second place, and the two can disagree — a preimage read
    /// back with `as_raw` does not check that its list was completed, so a wrong count would silently
    /// produce a wrong signature hash and therefore a wrong sender.
    pub(crate) fn append_signing_preimage(&self, stream: &mut rlp::RlpStream) {
        stream.clear();
        stream.append_raw(&[TYPE_BYTE], 0);
        stream.begin_unbounded_list();
        self.append_fields(stream);
        stream.finalize_unbounded_list();
    }

    /// The signing preimage as its own buffer, for a one-off caller.
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        self.append_signing_preimage(&mut stream);
        stream.out().to_vec()
    }
}

/// A signed EIP-1559 transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxEip1559 {
    /// The signed fields.
    pub tx: TxEip1559,
    /// The sender's signature.
    pub signature: TxSignature,
}

impl rlp::Encodable for SignedTxEip1559 {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(12);
        self.tx.append_fields(stream);
        append_signature(stream, &self.signature);
    }
}

impl SignedTxEip1559 {
    /// Decodes the twelve-item list that follows the type byte.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the list is not twelve strictly-tiling items, `to` is malformed, or
    /// `y_parity` is not 0 or 1.
    pub fn decode_strict(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 12)?;
        Ok(Self {
            tx: TxEip1559 {
                chain_id: rlp.val_at(0)?,
                nonce: rlp.val_at(1)?,
                max_priority_fee_per_gas: rlp.val_at(2)?,
                max_fee_per_gas: rlp.val_at(3)?,
                gas_limit: rlp.val_at(4)?,
                to: decode_destination(rlp, 5)?,
                value: rlp.val_at(6)?,
                data: rlp.val_at(7)?,
                access_list: decode_access_list(rlp, 8)?,
            },
            signature: decode_signature(rlp, 9)?,
        })
    }
}

impl TxEip1559 {
    /// This transaction's contribution to the execution environment, **consuming** it.
    ///
    /// Consuming rather than borrowing so that the owned fields — the call data, the access list and
    /// its storage keys — *move* instead of being copied. The executor takes them by value in the end,
    /// so a borrowing conversion would copy them once here and then hand the copy on; nothing reads the
    /// transaction after this point.
    ///
    /// `caller` is an argument because it is not a transaction field: it is what verifying the
    /// signature established.
    ///
    /// Every field is destructured by name. That is deliberate — adding a field to this type breaks
    /// this function, so a new consensus field cannot silently fail to reach execution.
    #[must_use]
    pub fn into_tx_env(self, caller: H160) -> TxEnv {
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
        } = self;

        TxEnv {
            tx_type: TxType::Eip1559,
            caller,
            tx_kind: to,
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
            authorization_list: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SignedTxEip1559, TYPE_BYTE};
    use crate::transaction::TxEnv;
    use crate::transaction::{TxKind, TxType};
    use hex_literal::hex;
    use primitive_types::H160;

    /// A real EIP-1559 transaction.
    const RAW: &[u8] = &hex!(
        "02f8b00142843b9aca008504a817c80082ad62946069a6c32cf691f5982febae4faf8a6f3ab2f0f680b844a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000c080a0840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565a025e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1"
    );

    fn decoded() -> SignedTxEip1559 {
        SignedTxEip1559::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap()
    }

    #[test]
    fn the_signing_preimage_omits_the_signature() {
        let typed = SignedTxEip1559::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap();
        let preimage = typed.tx.signing_preimage();
        assert_eq!(preimage[0], TYPE_BYTE);
        assert_eq!(rlp::Rlp::new(&preimage[1..]).item_count().unwrap(), 9);
    }

    /// Unlike the blob and set-code types, this one has a creation form.
    #[test]
    fn a_creation_is_representable() {
        let mut typed = SignedTxEip1559::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap();
        typed.tx.to = TxKind::Create;
        let encoded = rlp::encode(&typed).to_vec();
        assert_eq!(
            SignedTxEip1559::decode_strict(&rlp::Rlp::new(&encoded)).unwrap(),
            typed
        );
    }

    /// The projection into the execution payload: this type's own fields carried across, and every
    /// field it does not have written as its absent value. There is no impl back, so this is the only
    /// direction there is to check.
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

        assert_eq!(tx_type, TxType::Eip1559);
        assert_eq!(tx_kind, typed.tx.to);
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
        // The fee shape this type does not have is absent, not defaulted to a value.
        assert_eq!(gas_price, None);
        assert!(blob_versioned_hashes.is_empty());
        assert_eq!(max_fee_per_blob_gas, 0);
        assert_eq!(caller, H160::zero());
        assert!(authorization_list.is_empty());
    }
}
