//! The Ethereum block header and its RLP identity.
//!
//! [`Header`] follows consensus field order. Its RLP encoding defines the block hash through
//! [`Header::hash_slow`].

use crate::block::SealedHeader;
use crate::bloom::Bloom;
use crate::constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH};
use crate::crypto::keccak256;
use crate::eips::eip1559::{BaseFeeParams, calc_next_block_base_fee};
use crate::eips::eip7840::BlobParams;
use crate::errors::{HeaderField, InvalidHeader};
use crate::rlp_strict;
use core::cmp::Ordering;
use primitive_types::{H160, H256, U256};

/// Number of header fields present in every block since Frontier.
const MANDATORY_FIELDS: usize = 15;

/// Number of header fields once every post-Frontier extension is present.
const ALL_FIELDS: usize = 23;

/// An Ethereum block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Keccak-256 hash of the parent block's header.
    pub parent_hash: H256,
    /// Keccak-256 hash of the ommers list ([`EMPTY_OMMER_ROOT_HASH`] post-merge).
    pub ommers_hash: H256,
    /// Address that receives the block's priority fees (the coinbase).
    pub beneficiary: H160,
    /// Keccak-256 hash of the root of the world-state trie after this block has been executed
    /// and finalisations applied.
    pub state_root: H256,
    /// Keccak-256 hash of the root of the trie of this block's transactions.
    pub transactions_root: H256,
    /// Keccak-256 hash of the root of the trie of this block's receipts.
    pub receipts_root: H256,
    /// Bloom filter over every transaction log's address and topics.
    pub logs_bloom: Bloom,
    /// Proof-of-work difficulty; zero post-merge.
    pub difficulty: U256,
    /// Block height, genesis is zero.
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
    /// Proof-of-work nonce; an all-zero fixed-width byte string post-merge.
    pub nonce: [u8; 8],
    /// EIP-1559 base fee per gas, burned rather than paid to the beneficiary (London+).
    pub base_fee_per_gas: Option<u64>,
    /// Keccak-256 hash of the root of the trie of this block's validator withdrawals (EIP-4895,
    /// Shanghai+).
    pub withdrawals_root: Option<H256>,
    /// Blob gas consumed by the block's blob transactions (EIP-4844, Cancun+).
    pub blob_gas_used: Option<u64>,
    /// Running total of blob gas consumed above target before this block (EIP-4844, Cancun+).
    pub excess_blob_gas: Option<u64>,
    /// Parent beacon block root exposed to execution by EIP-4788 (Cancun+).
    pub parent_beacon_block_root: Option<H256>,
    /// Keccak-256 hash of the block's EIP-7685 request list (Prague+).
    pub requests_hash: Option<H256>,
    /// Keccak-256 hash of the block's access list (EIP-7928).
    pub block_access_list_hash: Option<H256>,
    /// Consensus-layer slot this block belongs to (EIP-7843).
    pub slot_number: Option<u64>,
}

impl AsRef<Self> for Header {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            parent_hash: H256::default(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: H160::default(),
            state_root: EMPTY_ROOT_HASH,
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: EMPTY_ROOT_HASH,
            logs_bloom: Bloom::default(),
            difficulty: U256::default(),
            number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Vec::new(),
            mix_hash: H256::default(),
            nonce: [0; 8],
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
            block_access_list_hash: None,
            slot_number: None,
        }
    }
}

impl Header {
    /// Computes the block hash: `keccak256(rlp(header))`.
    ///
    /// Named `slow` because it re-encodes the header on every call; prefer
    /// [`SealedHeader`], which caches the result.
    #[must_use]
    pub fn hash_slow(&self) -> H256 {
        keccak256(&rlp::encode(self))
    }

    /// Decodes exactly one header occupying all of `bytes`.
    ///
    /// Exactness is required when the input bytes define the header hash, as for witnessed ancestors.
    ///
    /// # Errors
    /// [`rlp::DecoderError`] for truncation, trailing bytes, length overflow or malformed fields.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, rlp::DecoderError> {
        let consumed = rlp_strict::declared_item_len(bytes)?;
        match consumed.cmp(&bytes.len()) {
            // The header declares a payload the buffer does not hold: too few bytes, not too many.
            Ordering::Greater => return Err(rlp::DecoderError::RlpIsTooShort),
            // The buffer holds bytes past the end of the header.
            Ordering::Less => return Err(rlp::DecoderError::RlpIsTooBig),
            Ordering::Equal => {}
        }
        rlp::decode(bytes)
    }

    /// Seals the header, computing and caching its hash.
    #[must_use]
    pub fn seal_slow(self) -> SealedHeader {
        SealedHeader::seal_slow(self)
    }

    /// Seals the header with a hash the caller already knows, without recomputing it.
    #[must_use]
    pub fn seal_unchecked(self, hash: H256) -> SealedHeader {
        SealedHeader::new_unchecked(self, hash)
    }

    /// Whether `ommers_hash` commits to an empty ommers list.
    #[must_use]
    pub fn ommers_hash_is_empty(&self) -> bool {
        self.ommers_hash == EMPTY_OMMER_ROOT_HASH
    }

    /// Whether the transactions trie is empty.
    #[must_use]
    pub fn transaction_root_is_empty(&self) -> bool {
        self.transactions_root == EMPTY_ROOT_HASH
    }

    /// Returns this block's EIP-4844 blob fee.
    ///
    /// Returns `None` if `excess_blob_gas` is absent or fee arithmetic overflows.
    #[must_use]
    pub fn blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        blob_params.calc_blob_fee(self.excess_blob_gas?)
    }

    /// Returns the next block's EIP-4844 blob fee.
    ///
    /// Returns `None` if a required header field is absent or fee arithmetic overflows.
    ///
    /// See [`Self::next_block_excess_blob_gas`].
    #[must_use]
    pub fn next_block_blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        blob_params.calc_blob_fee(self.next_block_excess_blob_gas(blob_params)?)
    }

    /// Calculates the next block's EIP-1559 base fee.
    ///
    /// Returns `None` if `base_fee_per_gas` is absent or the calculation fails.
    #[must_use]
    pub fn next_block_base_fee(&self, base_fee_params: BaseFeeParams) -> Option<u64> {
        calc_next_block_base_fee(
            self.gas_used,
            self.gas_limit,
            self.base_fee_per_gas?,
            base_fee_params,
        )
    }

    /// Calculates the next block's excess blob gas.
    ///
    /// Returns `None` if `excess_blob_gas`, `blob_gas_used`, or `base_fee_per_gas` is not set.
    #[must_use]
    pub fn next_block_excess_blob_gas(&self, blob_params: BlobParams) -> Option<u64> {
        blob_params.next_block_excess_blob_gas(
            self.excess_blob_gas?,
            self.blob_gas_used?,
            self.base_fee_per_gas?,
        )
    }

    /// Estimates the header's in-memory size as `size_of::<Header>() + extra_data.len()`.
    #[must_use]
    pub const fn size(&self) -> usize {
        size_of::<Self>() + self.extra_data.len()
    }

    /// Whether the header carries the Shanghai field.
    #[must_use]
    pub const fn shanghai_active(&self) -> bool {
        self.withdrawals_root.is_some()
    }

    /// Whether the header carries the first Cancun field.
    #[must_use]
    pub const fn cancun_active(&self) -> bool {
        self.blob_gas_used.is_some()
    }

    /// Whether the header carries the Prague field.
    #[must_use]
    pub const fn prague_active(&self) -> bool {
        self.requests_hash.is_some()
    }

    /// Whether the header carries the proposed Amsterdam field.
    #[must_use]
    pub const fn amsterdam_active(&self) -> bool {
        self.block_access_list_hash.is_some()
    }

    /// The first trailing field present while the one before it is absent, if any.
    ///
    /// Optional RLP fields are positional, so a gap has no consensus encoding: writing the later
    /// field shifts its meaning, while decoding can only produce a prefix.
    #[must_use]
    fn first_trailing_field_gap(&self) -> Option<HeaderField> {
        let present = [
            (HeaderField::BaseFeePerGas, self.base_fee_per_gas.is_some()),
            (
                HeaderField::WithdrawalsRoot,
                self.withdrawals_root.is_some(),
            ),
            (HeaderField::BlobGasUsed, self.blob_gas_used.is_some()),
            (HeaderField::ExcessBlobGas, self.excess_blob_gas.is_some()),
            (
                HeaderField::ParentBeaconBlockRoot,
                self.parent_beacon_block_root.is_some(),
            ),
            (HeaderField::RequestsHash, self.requests_hash.is_some()),
            (
                HeaderField::BlockAccessListHash,
                self.block_access_list_hash.is_some(),
            ),
            (HeaderField::SlotNumber, self.slot_number.is_some()),
        ];
        present
            .windows(2)
            .find(|pair| !pair[0].1 && pair[1].1)
            .map(|pair| pair[1].0)
    }

    /// The header's consensus RLP, or the reason it has none.
    ///
    /// Use this fallible form for a header assembled field by field: public optional fields can form
    /// a gap that the total [`rlp::Encodable`] trait cannot report. Decoded headers are prefixes by
    /// construction.
    ///
    /// # Errors
    /// [`InvalidHeader::TrailingFieldGap`] naming the first field present while an earlier one is
    /// absent. Nothing else can fail, which is why the trait impl stays total.
    pub fn encode_rlp(&self) -> Result<Vec<u8>, InvalidHeader> {
        if let Some(field) = self.first_trailing_field_gap() {
            return Err(InvalidHeader::TrailingFieldGap { field });
        }
        Ok(rlp::encode(self).to_vec())
    }
}

/// Decodes a canonical, fixed-width proof-of-work nonce without an intermediate allocation.
fn decode_nonce_at(rlp: &rlp::Rlp<'_>, index: usize) -> Result<[u8; 8], rlp::DecoderError> {
    rlp.at(index)?.decoder().decode_value(|bytes| {
        bytes
            .try_into()
            .map_err(|_| rlp::DecoderError::Custom("invalid nonce length"))
    })
}

/// Total RLP encoding for a header whose optional tail forms a prefix.
///
/// Use [`Header::encode_rlp`] when that invariant has not already been established.
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
        let items = rlp_strict::checked_len(rlp)?;
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
            // `Bloom` owns its fixed-width and canonical-string checks.
            logs_bloom: rlp.val_at(6)?,
            difficulty: rlp.val_at(7)?,
            number: rlp.val_at(8)?,
            gas_limit: rlp.val_at(9)?,
            gas_used: rlp.val_at(10)?,
            timestamp: rlp.val_at(11)?,
            extra_data: rlp.val_at(12)?,
            mix_hash: rlp.val_at(13)?,
            nonce: decode_nonce_at(rlp, 14)?,
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
    use crate::constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH};
    use crate::errors::{HeaderField, InvalidHeader};
    use crate::rlp_strict::overflowing_header;
    use hex_literal::hex;
    use primitive_types::{H256, U256};

    /// The Ethereum mainnet genesis header.
    fn mainnet_genesis() -> Header {
        Header {
            parent_hash: H256::zero(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
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

    /// `decode_exact` exists because a standalone header's hash is `keccak256` of exactly its bytes.
    /// The two ways a buffer can disagree with the header it declares are opposite faults, and each
    /// is reported as itself rather than folded into one "not exact".
    #[test]
    fn decode_exact_names_a_truncated_header_apart_from_a_padded_one() {
        let encoded = rlp::encode(&mainnet_genesis()).to_vec();
        assert_eq!(Header::decode_exact(&encoded).unwrap(), mainnet_genesis());

        // Bytes past the end of the header: they would be hashed but not decoded.
        let mut padded = encoded.clone();
        padded.push(0x00);
        assert_eq!(
            Header::decode_exact(&padded).unwrap_err(),
            rlp::DecoderError::RlpIsTooBig
        );

        // The header declares a payload the buffer does not hold: too few bytes, not too many.
        assert_eq!(
            Header::decode_exact(&encoded[..encoded.len() - 1]).unwrap_err(),
            rlp::DecoderError::RlpIsTooShort
        );

        // A declared length that overflows a `usize` is neither, and must not be summed: a header and
        // its length bytes from a witness would otherwise wrap or panic before any header was read.
        assert_eq!(
            Header::decode_exact(&overflowing_header(true)).unwrap_err(),
            rlp::DecoderError::RlpInvalidLength
        );
    }

    /// The genesis header with exactly the trailing fields `present` marks set, in encoder order.
    ///
    /// The values are arbitrary but distinct, so a field that lands in the wrong position is visible
    /// rather than coincidentally equal.
    fn with_trailing_fields(present: [bool; 8]) -> Header {
        Header {
            base_fee_per_gas: present[0].then_some(0x3b9a_ca00),
            withdrawals_root: present[1].then(|| H256::repeat_byte(0x11)),
            blob_gas_used: present[2].then_some(0x0002_0000),
            excess_blob_gas: present[3].then_some(0x0004_0000),
            parent_beacon_block_root: present[4].then(|| H256::repeat_byte(0x22)),
            requests_hash: present[5].then(|| H256::repeat_byte(0x33)),
            block_access_list_hash: present[6].then(|| H256::repeat_byte(0x44)),
            slot_number: present[7].then_some(0x1234),
            ..mainnet_genesis()
        }
    }

    /// Every combination of the eight trailing fields, as `[bool; 8]`.
    fn all_trailing_combinations() -> impl Iterator<Item = [bool; 8]> {
        (0u16..256).map(|bits| {
            let mut present = [false; 8];
            for (index, field) in present.iter_mut().enumerate() {
                *field = bits & (1 << index) != 0;
            }
            present
        })
    }

    /// The genesis header's RLP with item `index` replaced by the raw RLP fragment `raw`.
    ///
    /// Every other item comes from the encoder, so a rejection can only be about the substituted one.
    fn header_with_raw_item(index: usize, raw: &[u8]) -> Vec<u8> {
        let encoded = rlp::encode(&mainnet_genesis()).to_vec();
        let source = rlp::Rlp::new(&encoded);
        let count = source.item_count().unwrap();
        let mut stream = rlp::RlpStream::new_list(count);
        for position in 0..count {
            let item = if position == index {
                raw
            } else {
                source.at(position).unwrap().as_raw()
            };
            stream.append_raw(item, 1);
        }
        stream.out().to_vec()
    }

    /// The bloom is decoded by `Bloom`'s own decoder rather than by a width check restated here, so
    /// these cases pin that inheritance: `Header::decode` is the only place in production a bloom
    /// arrives from the wire, which makes it the only place `Bloom::decode`'s rules are load-bearing.
    #[test]
    fn a_header_bloom_must_be_exactly_256_bytes() {
        for width in [0usize, 8, 255, 257] {
            let raw = rlp::encode(&vec![0u8; width]).to_vec();
            assert_eq!(
                Header::decode_exact(&header_with_raw_item(6, &raw)).unwrap_err(),
                rlp::DecoderError::Custom("bloom filter is not 256 bytes"),
                "{width}-byte bloom"
            );
        }
    }

    /// A wrong *shape* is an RLP fault, not a width verdict. Both cases are ones `Rlp::data()` would
    /// have accepted, which is why the decoder goes through `decode_value`.
    #[test]
    fn a_header_bloom_must_be_a_canonical_string() {
        let mut list = rlp::RlpStream::new_list(1);
        list.append(&vec![0u8; 256]);
        assert_eq!(
            Header::decode_exact(&header_with_raw_item(6, &list.out())).unwrap_err(),
            rlp::DecoderError::RlpExpectedToBeData
        );
        // `0x01` has one encoding, and `0x81 0x01` is not it.
        assert_eq!(
            Header::decode_exact(&header_with_raw_item(6, &hex!("8101"))).unwrap_err(),
            rlp::DecoderError::RlpInvalidIndirection
        );
    }

    /// The nonce is a fixed 8-byte string, so a wrong width is refused rather than padded or
    /// trimmed — and refused without the value being copied first, however large it is.
    #[test]
    fn a_header_nonce_must_be_exactly_eight_bytes() {
        for width in [0usize, 7, 9, 32] {
            let raw = rlp::encode(&vec![0u8; width]).to_vec();
            assert_eq!(
                Header::decode_exact(&header_with_raw_item(14, &raw)).unwrap_err(),
                rlp::DecoderError::Custom("invalid nonce length"),
                "{width}-byte nonce"
            );
        }
        // The other half of "fixed-width, not a scalar": the genesis nonce's leading zeros survive
        // decoding verbatim, where an integer would have been required to drop them.
        assert_eq!(
            Header::decode_exact(&rlp::encode(&mainnet_genesis()))
                .unwrap()
                .nonce,
            hex!("0000000000000042")
        );
    }

    #[test]
    fn a_header_nonce_must_be_a_canonical_string() {
        let mut list = rlp::RlpStream::new_list(1);
        list.append(&vec![0u8; 8]);
        assert_eq!(
            Header::decode_exact(&header_with_raw_item(14, &list.out())).unwrap_err(),
            rlp::DecoderError::RlpExpectedToBeData
        );
        assert_eq!(
            Header::decode_exact(&header_with_raw_item(14, &hex!("8101"))).unwrap_err(),
            rlp::DecoderError::RlpInvalidIndirection
        );
    }

    /// Across all 256 shapes, only nine positional prefixes are encodable.
    #[test]
    fn encode_rlp_accepts_exactly_the_prefixes() {
        const FIELDS: [HeaderField; 8] = [
            HeaderField::BaseFeePerGas,
            HeaderField::WithdrawalsRoot,
            HeaderField::BlobGasUsed,
            HeaderField::ExcessBlobGas,
            HeaderField::ParentBeaconBlockRoot,
            HeaderField::RequestsHash,
            HeaderField::BlockAccessListHash,
            HeaderField::SlotNumber,
        ];

        let mut prefixes = 0;
        for present in all_trailing_combinations() {
            let header = with_trailing_fields(present);
            // The first field present while the one before it is absent, found independently.
            let gap = (1..8).find(|index| !present[index - 1] && present[*index]);
            match gap {
                None => {
                    prefixes += 1;
                    assert_eq!(
                        header.encode_rlp().unwrap(),
                        rlp::encode(&header).to_vec(),
                        "{present:?}"
                    );
                }
                Some(index) => assert_eq!(
                    header.encode_rlp().unwrap_err(),
                    InvalidHeader::TrailingFieldGap {
                        field: FIELDS[index]
                    },
                    "{present:?}"
                ),
            }
        }
        // One positional prefix per tail length, and no other shape.
        assert_eq!(prefixes, 9);
    }

    /// Every optional-tail prefix round-trips with its field count intact.
    #[test]
    fn every_prefix_of_the_trailing_fields_round_trips() {
        for count in 0..=8 {
            let mut present = [false; 8];
            present[..count].fill(true);
            let header = with_trailing_fields(present);
            let encoded = rlp::encode(&header).to_vec();
            assert_eq!(
                rlp::Rlp::new(&encoded).item_count().unwrap(),
                15 + count,
                "{count} trailing fields"
            );
            assert_eq!(
                Header::decode_exact(&encoded).unwrap(),
                header,
                "{count} trailing fields"
            );
        }
    }

    /// A `blob_gas_used` gap shifts one `u64` into the `base_fee_per_gas` position, producing valid
    /// bytes for a different header and therefore an ambiguous hash.
    #[test]
    fn encoding_a_gap_would_produce_a_different_header() {
        let mut present = [false; 8];
        present[2] = true;
        let gapped = with_trailing_fields(present);

        assert_eq!(
            gapped.encode_rlp().unwrap_err(),
            InvalidHeader::TrailingFieldGap {
                field: HeaderField::BlobGasUsed
            }
        );

        // What the refusal buys, reached through the total trait impl that does not check.
        let bytes = rlp::encode(&gapped).to_vec();
        let read_back = Header::decode_exact(&bytes).unwrap();
        assert_ne!(read_back, gapped);
        assert_eq!(read_back.base_fee_per_gas, gapped.blob_gas_used);
        assert_eq!(read_back.blob_gas_used, None);
        // One hash for two headers: the read-back header re-encodes to the very bytes the gapped one
        // produced, so the hash identifies neither.
        assert_eq!(read_back.hash_slow(), gapped.hash_slow());
        assert_eq!(rlp::encode(&read_back).to_vec(), bytes);
    }
}
