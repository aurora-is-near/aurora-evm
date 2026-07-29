//! The consensus form of a transaction: its payload plus the signature over it.
//!
//! [`SignedTransaction`] is what a block body carries and what a sender's identity is derived
//! *from*: it holds no sender field, because the sender is the result of checking the signature
//! against the [signature hash](SignedTransaction::signature_hash). Pairing the two produces the
//! execution form, [`Transaction`](crate::transaction::Transaction).

use crate::crypto::keccak256;
use crate::transaction::encode::{self, TxEncodeError};
use crate::transaction::payload::TxPayload;
use crate::transaction::signature::TxSignature;
use crate::transaction::signed_authorization::SignedAuthorization;
use crate::transaction::{AccessList, AccessListItem, TxKind, TxType};
use core::fmt;
use primitive_types::{H160, H256, U256};

/// A signed transaction, as it appears in a block body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The signed fields.
    pub payload: TxPayload,
    /// EIP-7702 signed authorization tuples; empty for every other type.
    pub authorization_list: Vec<SignedAuthorization>,
    /// The sender's signature over [`Self::signature_hash`].
    pub signature: TxSignature,
}

impl SignedTransaction {
    /// The hash the sender signed: `keccak256` of the transaction encoded without its signature.
    ///
    /// # Errors
    /// [`TxEncodeError`] if the payload's fields do not match its transaction type.
    pub fn signature_hash(&self) -> Result<H256, TxEncodeError> {
        let preimage = encode::encode(&self.payload, &self.authorization_list, None)?;
        Ok(keccak256(&preimage))
    }

    /// The EIP-2718 encoding of the transaction, signature included.
    ///
    /// This is the form the transactions trie and the transaction hash are built from.
    ///
    /// # Errors
    /// [`TxEncodeError`] if the payload's fields do not match its transaction type.
    pub fn encode_2718(&self) -> Result<Vec<u8>, TxEncodeError> {
        encode::encode(
            &self.payload,
            &self.authorization_list,
            Some(&self.signature),
        )
    }

    /// Decodes an EIP-2718 encoded transaction: a type byte followed by the field list, or a bare
    /// RLP list for a legacy transaction.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the input is empty, carries an unknown type byte, is not well-formed
    /// RLP for its type, or encodes a creation for a type that forbids one.
    pub fn decode_2718(bytes: &[u8]) -> Result<Self, TxDecodeError> {
        let (&first, _) = bytes.split_first().ok_or(TxDecodeError::Empty)?;
        // An RLP list header (>= 0xc0) means the legacy, un-prefixed form.
        if first >= 0xc0 {
            return Self::decode_legacy(&rlp::Rlp::new(bytes));
        }
        let tx_type = TxType::try_from(first).map_err(|_| TxDecodeError::UnknownTxType(first))?;
        if tx_type == TxType::Legacy {
            // `0x00` is not a valid envelope prefix: legacy transactions carry no type byte.
            return Err(TxDecodeError::UnknownTxType(first));
        }
        let rlp = rlp::Rlp::new(&bytes[1..]);
        match tx_type {
            TxType::Eip2930 => Self::decode_eip2930(&rlp),
            TxType::Eip1559 => Self::decode_eip1559(&rlp),
            TxType::Eip4844 => Self::decode_eip4844(&rlp),
            TxType::Eip7702 => Self::decode_eip7702(&rlp),
            TxType::Legacy => Err(TxDecodeError::UnknownTxType(first)),
        }
    }

    /// Legacy: nine items, whose `v` carries both the parity and (from EIP-155) the chain id.
    fn decode_legacy(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 9)?;
        let v: u64 = rlp.val_at(6)?;
        let (y_parity, chain_id) =
            TxSignature::from_legacy_v(v).ok_or(TxDecodeError::InvalidLegacyV(v))?;
        Ok(Self {
            payload: TxPayload {
                tx_type: TxType::Legacy,
                tx_kind: decode_destination(rlp, 3)?,
                gas_limit: rlp.val_at(2)?,
                value: rlp.val_at(4)?,
                data: rlp.val_at(5)?,
                nonce: rlp.val_at(0)?,
                chain_id,
                gas_price: Some(rlp.val_at(1)?),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                access_list: AccessList(Vec::new()),
                blob_versioned_hashes: Vec::new(),
                max_fee_per_blob_gas: 0,
            },
            authorization_list: Vec::new(),
            signature: TxSignature::new(y_parity, rlp.val_at(7)?, rlp.val_at(8)?),
        })
    }

    /// EIP-2930: the legacy fields, with a chain id in front and an access list at the end.
    fn decode_eip2930(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 11)?;
        Ok(Self {
            payload: TxPayload {
                tx_type: TxType::Eip2930,
                tx_kind: decode_destination(rlp, 4)?,
                gas_limit: rlp.val_at(3)?,
                value: rlp.val_at(5)?,
                data: rlp.val_at(6)?,
                nonce: rlp.val_at(1)?,
                chain_id: Some(rlp.val_at(0)?),
                gas_price: Some(rlp.val_at(2)?),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                access_list: decode_access_list(rlp, 7)?,
                blob_versioned_hashes: Vec::new(),
                max_fee_per_blob_gas: 0,
            },
            authorization_list: Vec::new(),
            signature: decode_signature(rlp, 8)?,
        })
    }

    /// EIP-1559: dynamic fees in place of `gas_price`.
    fn decode_eip1559(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 12)?;
        Ok(Self {
            payload: dynamic_fee_payload(rlp, TxType::Eip1559, decode_destination(rlp, 5)?)?,
            authorization_list: Vec::new(),
            signature: decode_signature(rlp, 9)?,
        })
    }

    /// EIP-4844: dynamic-fee fields, then the blob fee cap and the blob hashes.
    fn decode_eip4844(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 14)?;
        let mut payload = dynamic_fee_payload(
            rlp,
            TxType::Eip4844,
            decode_required_destination(rlp, 5, TxType::Eip4844)?,
        )?;
        payload.max_fee_per_blob_gas = decode_u128(rlp, 9)?;
        payload.blob_versioned_hashes = rlp
            .list_at::<H256>(10)?
            .into_iter()
            .map(|hash| U256::from_big_endian(hash.as_bytes()))
            .collect();
        Ok(Self {
            payload,
            authorization_list: Vec::new(),
            signature: decode_signature(rlp, 11)?,
        })
    }

    /// EIP-7702: dynamic-fee fields, then the signed authorization tuples.
    fn decode_eip7702(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 13)?;
        Ok(Self {
            payload: dynamic_fee_payload(
                rlp,
                TxType::Eip7702,
                decode_required_destination(rlp, 5, TxType::Eip7702)?,
            )?,
            authorization_list: rlp.list_at(9)?,
            signature: decode_signature(rlp, 10)?,
        })
    }
}

/// Builds the payload common to the dynamic-fee types from the first nine items.
fn dynamic_fee_payload(
    rlp: &rlp::Rlp<'_>,
    tx_type: TxType,
    tx_kind: TxKind,
) -> Result<TxPayload, TxDecodeError> {
    Ok(TxPayload {
        tx_type,
        tx_kind,
        gas_limit: rlp.val_at(4)?,
        value: rlp.val_at(6)?,
        data: rlp.val_at(7)?,
        nonce: rlp.val_at(1)?,
        chain_id: Some(rlp.val_at(0)?),
        gas_price: None,
        max_fee_per_gas: Some(rlp.val_at(3)?),
        max_priority_fee_per_gas: Some(rlp.val_at(2)?),
        access_list: decode_access_list(rlp, 8)?,
        blob_versioned_hashes: Vec::new(),
        max_fee_per_blob_gas: 0,
    })
}

/// Requires the item count an encoding of this type must have.
fn expect_items(rlp: &rlp::Rlp<'_>, expected: usize) -> Result<(), TxDecodeError> {
    if rlp.item_count()? == expected {
        Ok(())
    } else {
        Err(TxDecodeError::Rlp(rlp::DecoderError::RlpIncorrectListLen))
    }
}

/// Decodes `to`: an address, or a contract creation when the field is empty.
fn decode_destination(rlp: &rlp::Rlp<'_>, index: usize) -> Result<TxKind, TxDecodeError> {
    let bytes: Vec<u8> = rlp.val_at(index)?;
    if bytes.is_empty() {
        return Ok(TxKind::Create);
    }
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| TxDecodeError::InvalidDestination)?;
    Ok(TxKind::Call(H160(address)))
}

/// Decodes `to` for a type that has no creation form.
fn decode_required_destination(
    rlp: &rlp::Rlp<'_>,
    index: usize,
    tx_type: TxType,
) -> Result<TxKind, TxDecodeError> {
    match decode_destination(rlp, index)? {
        TxKind::Create => Err(TxDecodeError::CreateNotSupported(tx_type)),
        call @ TxKind::Call(_) => Ok(call),
    }
}

/// Decodes the access list: a list of `[address, [storage_key, ...]]` pairs.
fn decode_access_list(rlp: &rlp::Rlp<'_>, index: usize) -> Result<AccessList, TxDecodeError> {
    let list = rlp.at(index)?;
    let mut items = Vec::with_capacity(list.item_count()?);
    for item in &list {
        if item.item_count()? != 2 {
            return Err(TxDecodeError::Rlp(rlp::DecoderError::RlpIncorrectListLen));
        }
        items.push(AccessListItem {
            address: item.val_at(0)?,
            storage_keys: item.list_at(1)?,
        });
    }
    Ok(AccessList(items))
}

/// Decodes a typed transaction's `y_parity, r, s` tail.
fn decode_signature(rlp: &rlp::Rlp<'_>, index: usize) -> Result<TxSignature, TxDecodeError> {
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

/// Decodes a `u128`-valued field that is encoded as an RLP integer.
fn decode_u128(rlp: &rlp::Rlp<'_>, index: usize) -> Result<u128, TxDecodeError> {
    let value: U256 = rlp.val_at(index)?;
    if value.bits() > 128 {
        return Err(TxDecodeError::BlobFeeTooLarge);
    }
    Ok(value.low_u128())
}

/// Why an encoded transaction cannot be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxDecodeError {
    /// The input carried no bytes.
    Empty,
    /// The leading byte is not a known EIP-2718 type and not an RLP list header.
    UnknownTxType(u8),
    /// The input is not well-formed RLP for its transaction type.
    Rlp(rlp::DecoderError),
    /// A legacy `v` that encodes neither a pre-EIP-155 parity nor a chain id.
    InvalidLegacyV(u64),
    /// A typed transaction's `y_parity` was neither `0` nor `1`.
    InvalidYParity(u8),
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

impl fmt::Display for TxDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "no bytes to decode"),
            Self::UnknownTxType(byte) => write!(f, "unknown transaction type byte {byte:#04x}"),
            Self::Rlp(error) => write!(f, "malformed transaction RLP: {error}"),
            Self::InvalidLegacyV(v) => write!(f, "legacy signature `v` {v} is out of range"),
            Self::InvalidYParity(parity) => write!(f, "`y_parity` {parity} is not 0 or 1"),
            Self::InvalidDestination => write!(f, "`to` is neither empty nor a 20-byte address"),
            Self::CreateNotSupported(tx_type) => {
                write!(f, "{tx_type:?} transaction cannot be a contract creation")
            }
            Self::BlobFeeTooLarge => write!(f, "`max_fee_per_blob_gas` does not fit in a u128"),
        }
    }
}

impl core::error::Error for TxDecodeError {}

#[cfg(test)]
mod tests {
    use super::{SignedTransaction, TxDecodeError};
    use crate::crypto::keccak256;
    use crate::transaction::{TxKind, TxType};
    use hex_literal::hex;
    use primitive_types::H256;

    /// A consensus vector: raw EIP-2718 bytes together with the signature hash and transaction
    /// hash they must reproduce.
    ///
    /// The bytes and hashes come from Ethereum test fixtures (`TransactionTests`,
    /// `blockchain_tests`) and from alloy-consensus' own test vectors; each was cross-checked by
    /// recovering the signer from the signature hash and comparing it with the fixture's `sender`.
    struct Vector {
        name: &'static str,
        tx_type: TxType,
        raw: &'static [u8],
        signature_hash: [u8; 32],
        transaction_hash: Option<[u8; 32]>,
    }

    fn vectors() -> Vec<Vector> {
        vec![
            Vector {
                name: "legacy, pre-EIP-155 (v = 28)",
                tx_type: TxType::Legacy,
                raw: &hex!(
                    "f85f800182520894000000000000000000000000000b9331677e6ebf0a801ca098ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa01887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3"
                ),
                signature_hash: hex!(
                    "9f8e5c24b9b3a0664a9f8b358c07ea710e5a40b82d40abf75f68029708744dda"
                ),
                transaction_hash: Some(hex!(
                    "2781a1444a7a4a646bf551f90913054dc47b2f3493d4a82a057445eb9e1c98cf"
                )),
            },
            Vector {
                name: "legacy, EIP-155 chain id 1 (v = 37)",
                tx_type: TxType::Legacy,
                raw: &hex!(
                    "f9015482078b8505d21dba0083022ef1947a250d5630b4cf539739df2c5dacb4c659f2488d880c46549a521b13d8b8e47ff36ab50000000000000000000000000000000000000000000066ab5a608bd00a23f2fe000000000000000000000000000000000000000000000000000000000000008000000000000000000000000048c04ed5691981c42154c6167398f95e8f38a7ff00000000000000000000000000000000000000000000000000000000632ceac70000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006c6ee5e31d828de241282b9606c8e98ea48526e225a0c9077369501641a92ef7399ff81c21639ed4fd8fc69cb793cfa1dbfab342e10aa0615facb2f1bcf3274a354cfe384a38d0cc008a11c2dd23a69111bc6930ba27a8"
                ),
                signature_hash: hex!(
                    "379ff32b417de419215242f8c5c2f7fe533948b45f0dbe842f7300f889b263ef"
                ),
                transaction_hash: None,
            },
            Vector {
                name: "EIP-2930 with a non-empty access list",
                tx_type: TxType::Eip2930,
                raw: &hex!(
                    "01f89b01800a8301e974943068947c19dbbc5a170610a69c65e341f0a0b7458080f838f7940000000000000000000000000000000000000000e1a0000000000000000000000000000000000000000000000000000000000000000001a0712d63f4983ce033255f9adfe3b159f465766eac906591091e3ad03ffc06ad16a0078e21a3501b9fc9b9b9e223cc19768be044d5c7c6faf1fbc0f5aa4deb325fe9"
                ),
                signature_hash: hex!(
                    "aa9a862c95f3f72aa762fb89951dccb593f1c3078cb258480a78b7728f94fc5b"
                ),
                transaction_hash: None,
            },
            Vector {
                name: "EIP-1559",
                tx_type: TxType::Eip1559,
                raw: &hex!(
                    "02f8b00142843b9aca008504a817c80082ad62946069a6c32cf691f5982febae4faf8a6f3ab2f0f680b844a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000c080a0840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565a025e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1"
                ),
                signature_hash: hex!(
                    "0d5688ac3897124635b6cf1bc0e29d6dfebceebdc10a54d74f2ef8b56535b682"
                ),
                transaction_hash: Some(hex!(
                    "0ec0b6a2df4d87424e5f6ad2a654e27aaeb7dac20ae9e8385cc09087ad532ee0"
                )),
            },
            Vector {
                name: "EIP-4844 with one blob hash",
                tx_type: TxType::Eip4844,
                raw: &hex!(
                    "03f8a601808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a0000000000000000000000000000000000000000000000000000000000000000cc001e1a0010000000000000000000000000000000000000000000000000000000000000001a08cdee4f529448c31aef67fb75346f7e0279e9545da3194191835349e19888b41a013e7d078013af8d334a2b09246dad964099443bb85b20d40bb3b08ea3c93229f"
                ),
                signature_hash: hex!(
                    "688f454d4448cc14d98f22b6746b360973cfc228844d9716f2e53c5ed11cf80d"
                ),
                transaction_hash: Some(hex!(
                    "fdfacacf596fb56f91cac5b5d6f076cba9681e26f05828e51e719693b18f9418"
                )),
            },
            Vector {
                name: "EIP-7702 with one authorization",
                tx_type: TxType::Eip7702,
                raw: &hex!(
                    "04f8e101808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a0000000000000000000000000000000000000000000000000000000000000000cc0f85cf85a809400000000000000000000000000000000000000008080a085044e88414585239b3b7b4f91c0bc6275ed817b925d973869370ca9b842925aa02e021ec5210eb0cc051524a05e9049d6a57acdf0386e3feeae658df6d2a242a980a0f2e0c327202f18c44b074c628433f8d7ed09f7fbe180684f1ab6da84b8d94c4aa00c755520f565a678bac8959549dba76a7c2120025b53e1565b09845880a66dbf"
                ),
                signature_hash: hex!(
                    "304c3e702781b1eb9ec3e70d7f9457d7c8f3f4ce053124149b8e78f0b066c823"
                ),
                transaction_hash: None,
            },
        ]
    }

    #[test]
    fn decoding_recognises_every_transaction_type() {
        for vector in vectors() {
            let tx = SignedTransaction::decode_2718(vector.raw)
                .unwrap_or_else(|err| panic!("{}: {err}", vector.name));
            assert_eq!(tx.payload.tx_type, vector.tx_type, "{}", vector.name);
        }
    }

    #[test]
    fn reencoding_reproduces_the_consensus_bytes() {
        // The strongest check on the encoder: the envelope must come back byte-identical to the
        // bytes the fixtures carry, field order and integer forms included.
        for vector in vectors() {
            let tx = SignedTransaction::decode_2718(vector.raw).unwrap();
            assert_eq!(
                tx.encode_2718().unwrap(),
                vector.raw.to_vec(),
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn signature_hash_matches_the_expected_preimage() {
        // The consensus-critical part: the signing preimage differs from the envelope in its tail,
        // so it cannot be validated by re-encoding alone.
        for vector in vectors() {
            let tx = SignedTransaction::decode_2718(vector.raw).unwrap();
            assert_eq!(
                tx.signature_hash().unwrap(),
                H256(vector.signature_hash),
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn transaction_hash_is_keccak_of_the_envelope() {
        for vector in vectors() {
            if let Some(expected) = vector.transaction_hash {
                let tx = SignedTransaction::decode_2718(vector.raw).unwrap();
                assert_eq!(
                    keccak256(&tx.encode_2718().unwrap()),
                    H256(expected),
                    "{}",
                    vector.name
                );
            }
        }
    }

    #[test]
    fn legacy_chain_id_comes_from_v_and_drives_the_preimage() {
        let pre_155 = SignedTransaction::decode_2718(vectors()[0].raw).unwrap();
        assert_eq!(pre_155.payload.chain_id, None);
        let eip155 = SignedTransaction::decode_2718(vectors()[1].raw).unwrap();
        assert_eq!(eip155.payload.chain_id, Some(1));

        // Dropping the chain id switches the legacy preimage from nine fields to six, so the hash
        // must change: this is what makes `chain_id` part of what was signed.
        let mut without_chain_id = eip155.clone();
        without_chain_id.payload.chain_id = None;
        assert_ne!(
            without_chain_id.signature_hash().unwrap(),
            eip155.signature_hash().unwrap()
        );
    }

    #[test]
    fn blob_hashes_keep_their_leading_zeros() {
        // A blob hash is a 32-byte string, not an integer: encoding it as an integer would strip
        // the leading zero byte of a hash like `0x00ff..` and change the signature hash.
        let mut with_leading_zero = SignedTransaction::decode_2718(vectors()[4].raw).unwrap();
        with_leading_zero.payload.blob_versioned_hashes = vec![primitive_types::U256::from(255u64)];
        let encoded = with_leading_zero.encode_2718().unwrap();
        // 0xa0 introduces a 32-byte string; the hash contributes 31 zero bytes then 0xff.
        assert!(
            encoded.windows(33).any(|window| window[0] == 0xa0
                && window[1..32] == [0u8; 31]
                && window[32] == 0xff),
            "blob hash was not encoded as a 32-byte string"
        );
    }

    #[test]
    fn decoding_rejects_malformed_input() {
        assert_eq!(
            SignedTransaction::decode_2718(&[]).unwrap_err(),
            TxDecodeError::Empty
        );
        // `0x00` is not a valid envelope prefix, and neither is an unassigned type byte.
        assert_eq!(
            SignedTransaction::decode_2718(&[0x00, 0xc0]).unwrap_err(),
            TxDecodeError::UnknownTxType(0x00)
        );
        assert_eq!(
            SignedTransaction::decode_2718(&[0x7f, 0xc0]).unwrap_err(),
            TxDecodeError::UnknownTxType(0x7f)
        );
        // A truncated list of the right shape but the wrong length.
        let mut stream = rlp::RlpStream::new_list(3);
        stream.append(&1u64);
        stream.append(&2u64);
        stream.append(&3u64);
        assert!(SignedTransaction::decode_2718(&stream.out()).is_err());
    }

    #[test]
    fn create_is_rejected_for_the_types_that_forbid_it() {
        // Take the 4844 vector and blank its destination: the type has no creation form, so both
        // decoding such bytes and encoding such a payload must fail.
        let mut create = SignedTransaction::decode_2718(vectors()[4].raw).unwrap();
        create.payload.tx_kind = TxKind::Create;
        assert!(create.encode_2718().is_err());
        assert!(create.signature_hash().is_err());
    }
}
