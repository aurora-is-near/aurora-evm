//! [EIP-4844] blob transaction, type byte `0x03`.
//!
//! Only the **consensus** form is modelled: the versioned hashes a block commits to. The network
//! form, which carries the blobs, commitments and proofs, exists for transaction gossip and never
//! appears inside a block, so a validator never sees one.
//!
//! [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844

use super::codec::{
    TxDecodeError, append_access_list, append_blob_hashes, append_signature, decode_access_list,
    decode_required_destination, decode_signature, decode_u128, expect_items,
};
use crate::rlp_strict;
use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, TxKind, TxType};
use primitive_types::{H160, H256, U256};

/// The EIP-4844 type byte.
pub const TYPE_BYTE: u8 = 0x03;

/// A blob transaction's own fields.
///
/// `to` is an `H160` rather than a [`TxKind`]: a blob transaction has no creation form, so making it
/// unrepresentable is cheaper than checking for it. `blob_versioned_hashes` are `H256` for the same
/// reason — they are hashes, and the fixed width is what keeps their leading zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEip4844 {
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
    /// Destination. A blob transaction cannot be a creation.
    pub to: H160,
    /// Value transferred.
    pub value: U256,
    /// Call data.
    pub data: Vec<u8>,
    /// Addresses and storage slots pre-warmed for this transaction.
    pub access_list: AccessList,
    /// Most the sender will pay per unit of blob gas.
    pub max_fee_per_blob_gas: u128,
    /// KZG versioned hashes of the blobs this transaction carries.
    pub blob_versioned_hashes: Vec<H256>,
}

impl TxEip4844 {
    /// The eleven transaction fields shared by the signed envelope and the encoding for signing.
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
        stream.append(&U256::from(self.max_fee_per_blob_gas));
        append_blob_hashes(stream, &self.blob_versioned_hashes);
    }

    /// Encodes this transaction for signing into `stream`, clearing it first.
    ///
    /// An unbounded list derives its arity from the fields written, avoiding a duplicated manual
    /// count before the encoding is hashed through `as_raw`.
    pub(crate) fn encode_for_signing_in(&self, stream: &mut rlp::RlpStream) {
        stream.clear();
        stream.append_raw(&[TYPE_BYTE], 0);
        stream.begin_unbounded_list();
        self.append_fields(stream);
        stream.finalize_unbounded_list();
    }

    /// The consensus encoding hashed to produce this transaction's signature hash.
    #[must_use]
    pub fn encoded_for_signing(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        self.encode_for_signing_in(&mut stream);
        stream.out().to_vec()
    }
}

/// A signed blob transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxEip4844 {
    /// The signed fields.
    pub tx: TxEip4844,
    /// The sender's signature.
    pub signature: TxSignature,
}

impl rlp::Encodable for SignedTxEip4844 {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(14);
        self.tx.append_fields(stream);
        append_signature(stream, &self.signature);
    }
}

impl SignedTxEip4844 {
    /// Decodes the fourteen-item list that follows the type byte.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the list is not fourteen strictly-tiling items, the transaction is a
    /// creation, `max_fee_per_blob_gas` overflows a `u128`, or `y_parity` is not 0 or 1.
    pub fn decode_strict(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 14)?;
        Ok(Self {
            tx: TxEip4844 {
                chain_id: rlp.val_at(0)?,
                nonce: rlp.val_at(1)?,
                max_priority_fee_per_gas: rlp.val_at(2)?,
                max_fee_per_gas: rlp.val_at(3)?,
                gas_limit: rlp.val_at(4)?,
                to: decode_required_destination(rlp, 5, TxType::Eip4844)?,
                value: rlp.val_at(6)?,
                data: rlp.val_at(7)?,
                access_list: decode_access_list(rlp, 8)?,
                max_fee_per_blob_gas: decode_u128(rlp, 9)?,
                blob_versioned_hashes: rlp_strict::checked_list_at(rlp, 10)?,
            },
            signature: decode_signature(rlp, 11)?,
        })
    }
}

impl TxEip4844 {
    /// Consumes the transaction into its execution fields for the recovered `caller`.
    ///
    /// Owned data moves without cloning. Named destructuring makes a newly added consensus field a
    /// compile-time update point for this projection.
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
            max_fee_per_blob_gas,
            blob_versioned_hashes,
        } = self;

        TxEnv {
            tx_type: TxType::Eip4844,
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
            // The one conversion that cannot be a move: the hashes are `H256` here and `U256` in the
            // environment, and no safe cast reuses a `Vec`'s storage across element types. Bounded by
            // the per-transaction blob limit, so it is a handful of words.
            blob_versioned_hashes: blob_versioned_hashes
                .into_iter()
                .map(|hash| U256::from_big_endian(hash.as_bytes()))
                .collect(),
            max_fee_per_blob_gas,
            authorization_list: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SignedTxEip4844, TYPE_BYTE};
    use crate::transaction::TxEnv;
    use crate::transaction::{TxKind, TxType};
    use hex_literal::hex;
    use primitive_types::H160;
    use primitive_types::H256;
    use primitive_types::U256;

    /// A real blob transaction.
    const RAW: &[u8] = &hex!(
        "03f8a601808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a00000"
        "00000000000000000000000000000000000000000000000000000000000cc001e1a00100"
        "00000000000000000000000000000000000000000000000000000000000001a08cdee4f5"
        "29448c31aef67fb75346f7e0279e9545da3194191835349e19888b41a013e7d078013af8"
        "d334a2b09246dad964099443bb85b20d40bb3b08ea3c93229f"
    );

    fn decoded() -> SignedTxEip4844 {
        SignedTxEip4844::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap()
    }

    /// A versioned hash whose first byte is `0x01` and whose remaining bytes are zero: encoded as an
    /// integer it would lose 31 leading zeros, so the fixed width is what makes the round trip work.
    #[test]
    fn blob_hashes_keep_their_leading_zeros() {
        let typed = decoded();
        let hash = typed.tx.blob_versioned_hashes[0];
        assert_eq!(hash.as_bytes()[0], 0x01);
        assert!(hash.as_bytes()[1..].iter().all(|byte| *byte == 0));
        // The projection widens them into `U256`, and the value must survive that too.
        let payload = typed.tx.into_tx_env(H160::zero());
        assert_eq!(payload.blob_versioned_hashes.len(), 1);
        assert_eq!(payload.blob_versioned_hashes[0], U256::from(1u64) << 248);
    }

    #[test]
    fn the_encoding_for_signing_omits_the_signature() {
        let encoded = decoded().tx.encoded_for_signing();
        assert_eq!(encoded[0], TYPE_BYTE);
        assert_eq!(rlp::Rlp::new(&encoded[1..]).item_count().unwrap(), 11);
    }

    #[test]
    fn a_blob_fee_wider_than_a_u128_is_rejected() {
        let rlp = rlp::Rlp::new(&RAW[1..]);
        let mut stream = rlp::RlpStream::new_list(14);
        for i in 0..14usize {
            if i == 9 {
                stream.append(&H256::repeat_byte(0xff)); // 2^256 - 1, far past a u128
            } else {
                stream.append_raw(rlp.at(i).unwrap().as_raw(), 1);
            }
        }
        assert!(SignedTxEip4844::decode_strict(&rlp::Rlp::new(&stream.out())).is_err());
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

        assert_eq!(tx_type, TxType::Eip4844);
        // `to` is an `H160` on the type, so the union's `TxKind` can only be a call.
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
        assert_eq!(max_fee_per_blob_gas, typed.tx.max_fee_per_blob_gas);
        // Widened from `H256` to `U256`, and the leading zeros must survive it.
        assert_eq!(blob_versioned_hashes, vec![U256::from(1u64) << 248]);
        assert_eq!(gas_price, None);
        assert_eq!(caller, H160::zero());
        assert!(authorization_list.is_empty());
    }
}
