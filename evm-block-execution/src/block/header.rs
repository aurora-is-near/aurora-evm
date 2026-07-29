//! The Ethereum block header and its RLP identity.
//!
//! [`Header`] is the canonical header: the same fields, in the same order, that the Yellow Paper
//! and the post-merge EIPs define, expressed over [`primitive_types`] instead of an external
//! consensus crate. Its RLP encoding is what the block hash is computed from
//! ([`Header::hash_slow`]), so the field order and the encoding of every field are
//! consensus-critical.
//!
//! Fields introduced after Frontier are `Option`, and they are appended to the RLP list **only
//! when present**, in fork-activation order: `base_fee_per_gas` (London, EIP-1559),
//! `withdrawals_root` (Shanghai, EIP-4895), `blob_gas_used` / `excess_blob_gas` (Cancun,
//! EIP-4844), `parent_beacon_block_root` (Cancun, EIP-4788), `requests_hash` (Prague, EIP-7685),
//! `block_access_list_hash` (EIP-7928) and `slot_number` (EIP-7843). A header must therefore
//! populate them in that order — a `Some` after a `None` would shift every later field's position
//! in the list and produce a different hash.

use crate::bloom::Bloom;
use crate::crypto::keccak256;
use primitive_types::{H160, H256, U256};

/// Number of header fields present in every block since Frontier.
const MANDATORY_FIELDS: usize = 15;

/// Number of header fields once every post-Frontier extension is present.
const ALL_FIELDS: usize = 23;

/// An Ethereum block header.
///
/// The `Option` fields are absent before the fork that introduced them; see the module docs for
/// their RLP ordering. This type deliberately does not derive `serde`: `logs_bloom` is a 256-byte
/// [`Bloom`] and serde has no built-in impl for arrays that large.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Keccak-256 hash of the parent block's header.
    pub parent_hash: H256,
    /// Keccak-256 hash of the ommers list (`EMPTY_OMMERS_HASH` post-merge).
    pub ommers_hash: H256,
    /// Address that receives the block's priority fees (the coinbase).
    pub beneficiary: H160,
    /// Root of the world-state trie after this block has been executed.
    pub state_root: H256,
    /// Root of the trie of this block's transactions.
    pub transactions_root: H256,
    /// Root of the trie of this block's receipts.
    pub receipts_root: H256,
    /// Bloom filter over the addresses and topics of every log in the block.
    pub logs_bloom: Bloom,
    /// Proof-of-work difficulty; zero post-merge.
    pub difficulty: U256,
    /// Block height (genesis is zero).
    pub number: u64,
    /// Maximum gas the block may consume.
    pub gas_limit: u64,
    /// Gas actually consumed by the block's transactions.
    pub gas_used: u64,
    /// Unix timestamp of the block.
    pub timestamp: u64,
    /// Free-form data chosen by the proposer (at most 32 bytes).
    pub extra_data: Vec<u8>,
    /// Proof-of-work mix hash; post-merge this carries the beacon chain's `prevrandao`.
    pub mix_hash: H256,
    /// Proof-of-work nonce; all-zero post-merge. A fixed 8-byte string, never a scalar.
    pub nonce: [u8; 8],
    /// EIP-1559 base fee per gas, burned rather than paid to the beneficiary (London+).
    pub base_fee_per_gas: Option<u64>,
    /// Root of the trie of this block's validator withdrawals (EIP-4895, Shanghai+).
    pub withdrawals_root: Option<H256>,
    /// Blob gas consumed by the block's blob transactions (EIP-4844, Cancun+).
    pub blob_gas_used: Option<u64>,
    /// Running total of blob gas consumed above target before this block (EIP-4844, Cancun+).
    pub excess_blob_gas: Option<u64>,
    /// Parent beacon block root, exposed to the EVM by EIP-4788 (Cancun+).
    pub parent_beacon_block_root: Option<H256>,
    /// Hash of the block's EIP-7685 request list (Prague+).
    pub requests_hash: Option<H256>,
    /// Hash of the block's access list (EIP-7928).
    pub block_access_list_hash: Option<H256>,
    /// Consensus-layer slot this block belongs to (EIP-7843).
    pub slot_number: Option<u64>,
}

impl Header {
    /// Computes the block hash: `keccak256(rlp(header))`.
    ///
    /// Named `_slow` because it re-encodes the header on every call; prefer
    /// [`SealedHeader`](super::SealedHeader), which caches the result.
    #[must_use]
    pub fn hash_slow(&self) -> H256 {
        keccak256(&rlp::encode(self))
    }

    /// Seals the header, computing and caching its hash.
    #[must_use]
    pub fn seal_slow(self) -> super::SealedHeader {
        super::SealedHeader::seal_slow(self)
    }

    /// Seals the header with a hash the caller already knows, without recomputing it.
    #[must_use]
    pub fn seal_unchecked(self, hash: H256) -> super::SealedHeader {
        super::SealedHeader::new(self, hash)
    }

    /// Whether this header carries an EIP-1559 base fee (London+).
    #[must_use]
    pub const fn is_eip1559(&self) -> bool {
        self.base_fee_per_gas.is_some()
    }

    /// Blob gas excess and used, present together from Cancun on.
    #[must_use]
    pub const fn blob_gas(&self) -> Option<(u64, u64)> {
        match (self.excess_blob_gas, self.blob_gas_used) {
            (Some(excess), Some(used)) => Some((excess, used)),
            _ => None,
        }
    }
}

/// Reads a fixed-size byte string from position `index` of an RLP list.
fn fixed_bytes_at<const N: usize>(
    rlp: &rlp::Rlp<'_>,
    index: usize,
    field: &'static str,
) -> Result<[u8; N], rlp::DecoderError> {
    let bytes: Vec<u8> = rlp.val_at(index)?;
    bytes
        .try_into()
        .map_err(|_| rlp::DecoderError::Custom(field))
}

impl rlp::Encodable for Header {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        // Unbounded: the number of items depends on which post-Frontier fields are present.
        stream.begin_unbounded_list();
        stream.append(&self.parent_hash);
        stream.append(&self.ommers_hash);
        stream.append(&self.beneficiary);
        stream.append(&self.state_root);
        stream.append(&self.transactions_root);
        stream.append(&self.receipts_root);
        stream.append(&self.logs_bloom);
        stream.append(&self.difficulty);
        stream.append(&self.number);
        stream.append(&self.gas_limit);
        stream.append(&self.gas_used);
        stream.append(&self.timestamp);
        stream.append(&self.extra_data);
        stream.append(&self.mix_hash);
        // A fixed 8-byte string: appending the scalar would strip its leading zeros.
        stream.append(&self.nonce.as_slice());

        // Post-Frontier fields, appended only when present, in fork-activation order.
        if let Some(base_fee_per_gas) = self.base_fee_per_gas {
            stream.append(&base_fee_per_gas);
        }
        if let Some(withdrawals_root) = self.withdrawals_root {
            stream.append(&withdrawals_root);
        }
        if let Some(blob_gas_used) = self.blob_gas_used {
            stream.append(&blob_gas_used);
        }
        if let Some(excess_blob_gas) = self.excess_blob_gas {
            stream.append(&excess_blob_gas);
        }
        if let Some(parent_beacon_block_root) = self.parent_beacon_block_root {
            stream.append(&parent_beacon_block_root);
        }
        if let Some(requests_hash) = self.requests_hash {
            stream.append(&requests_hash);
        }
        if let Some(block_access_list_hash) = self.block_access_list_hash {
            stream.append(&block_access_list_hash);
        }
        if let Some(slot_number) = self.slot_number {
            stream.append(&slot_number);
        }
        stream.finalize_unbounded_list();
    }
}

impl rlp::Decodable for Header {
    fn decode(rlp: &rlp::Rlp<'_>) -> Result<Self, rlp::DecoderError> {
        let items = rlp.item_count()?;
        if !(MANDATORY_FIELDS..=ALL_FIELDS).contains(&items) {
            return Err(rlp::DecoderError::RlpIncorrectListLen);
        }

        let mut header = Self {
            parent_hash: rlp.val_at(0)?,
            ommers_hash: rlp.val_at(1)?,
            beneficiary: rlp.val_at(2)?,
            state_root: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            receipts_root: rlp.val_at(5)?,
            logs_bloom: Bloom(fixed_bytes_at(rlp, 6, "invalid logs bloom length")?),
            difficulty: rlp.val_at(7)?,
            number: rlp.val_at(8)?,
            gas_limit: rlp.val_at(9)?,
            gas_used: rlp.val_at(10)?,
            timestamp: rlp.val_at(11)?,
            extra_data: rlp.val_at(12)?,
            mix_hash: rlp.val_at(13)?,
            nonce: fixed_bytes_at(rlp, 14, "invalid nonce length")?,
            ..Self::default()
        };

        // Trailing fields are positional: each is present only if the ones before it are.
        if items > 15 {
            header.base_fee_per_gas = Some(rlp.val_at(15)?);
        }
        if items > 16 {
            header.withdrawals_root = Some(rlp.val_at(16)?);
        }
        if items > 17 {
            header.blob_gas_used = Some(rlp.val_at(17)?);
        }
        if items > 18 {
            header.excess_blob_gas = Some(rlp.val_at(18)?);
        }
        if items > 19 {
            header.parent_beacon_block_root = Some(rlp.val_at(19)?);
        }
        if items > 20 {
            header.requests_hash = Some(rlp.val_at(20)?);
        }
        if items > 21 {
            header.block_access_list_hash = Some(rlp.val_at(21)?);
        }
        if items > 22 {
            header.slot_number = Some(rlp.val_at(22)?);
        }
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::Header;
    use crate::constants::{EMPTY_OMMERS_HASH, EMPTY_ROOT_HASH};
    use hex_literal::hex;
    use primitive_types::{H256, U256};

    /// The Ethereum mainnet genesis header.
    fn mainnet_genesis() -> Header {
        Header {
            parent_hash: H256::zero(),
            ommers_hash: EMPTY_OMMERS_HASH,
            state_root: H256(hex!(
                "d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"
            )),
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: EMPTY_ROOT_HASH,
            difficulty: U256::from(0x4_0000_0000u64),
            gas_limit: 0x1388,
            extra_data: hex!("11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa")
                .to_vec(),
            nonce: hex!("0000000000000042"),
            ..Header::default()
        }
    }

    #[test]
    fn mainnet_genesis_hash_matches() {
        // The canonical mainnet genesis hash: proves the field order and the encoding of each
        // field (notably the 8-byte `nonce` string and the scalar `difficulty`/`gas_limit`).
        assert_eq!(
            mainnet_genesis().hash_slow(),
            H256(hex!(
                "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            ))
        );
    }

    #[test]
    fn rlp_roundtrip_frontier_header() {
        let header = mainnet_genesis();
        let encoded = rlp::encode(&header);
        let decoded: Header = rlp::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        // Exactly the 15 pre-London fields, no trailing entries.
        assert_eq!(rlp::Rlp::new(&encoded).item_count().unwrap(), 15);
    }

    #[test]
    fn rlp_roundtrip_with_all_optional_fields() {
        let mut header = mainnet_genesis();
        header.base_fee_per_gas = Some(1_000_000_000);
        header.withdrawals_root = Some(EMPTY_ROOT_HASH);
        header.blob_gas_used = Some(131_072);
        header.excess_blob_gas = Some(262_144);
        header.parent_beacon_block_root = Some(H256::repeat_byte(0xbe));
        header.requests_hash = Some(H256::repeat_byte(0x7e));
        header.block_access_list_hash = Some(H256::repeat_byte(0x79));
        header.slot_number = Some(42);

        let encoded = rlp::encode(&header);
        assert_eq!(rlp::Rlp::new(&encoded).item_count().unwrap(), 23);
        let decoded: Header = rlp::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn optional_fields_shift_the_hash() {
        // A trailing field changes the RLP list, hence the block hash: the positional encoding is
        // what makes the fork order load-bearing.
        let frontier = mainnet_genesis();
        let mut london = frontier.clone();
        london.base_fee_per_gas = Some(7);
        assert_ne!(frontier.hash_slow(), london.hash_slow());
    }

    #[test]
    fn decode_rejects_a_truncated_list() {
        let mut stream = rlp::RlpStream::new_list(3);
        stream.append(&H256::zero());
        stream.append(&H256::zero());
        stream.append(&H256::zero());
        let encoded = stream.out();
        assert!(rlp::decode::<Header>(&encoded).is_err());
    }
}
