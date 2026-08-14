//! The Ethereum block header and its RLP identity.
//!
//! [`Header`] is the canonical header: the same fields, in the same order, that the Yellow Paper
//! and the post-merge EIPs define. Its RLP encoding is what the block hash is computed from
//! ([`Header::hash_slow`]), so the field order and the encoding of every field are
//! consensus-critical.

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
    /// Keccak-256 hash of the ommers list ([`EMPTY_OMMER_ROOT_HASH`](crate::constants::EMPTY_OMMER_ROOT_HASH)
    /// post-merge).
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
    /// The Bloom filter composed from indexable information (logger address and log topics)
    /// contained in each log entry from the receipt of each transaction in the transactions list;
    /// formally Hb.
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
    /// Proof-of-work nonce; all-zero post-merge. A fixed 8-byte string, never a scalar.
    /// Value which, combined with the mixhash, proves that a sufficient amount of
    /// computation has been carried out on this block
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
    /// The hash of the parent beacon block's root is included in execution blocks, as proposed by
    /// EIP-4788 (Cancun+).
    ///
    /// This enables trust-minimized access to consensus state, supporting staking pools, bridges,
    /// and more.
    ///
    /// The beacon roots contract handles root storage, enhancing Ethereum's functionalities.
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
    /// [`SealedHeader`](SealedHeader), which caches the result.
    #[must_use]
    pub fn hash_slow(&self) -> H256 {
        keccak256(&rlp::encode(self))
    }

    /// Decodes a header that must occupy `bytes` **entirely**.
    ///
    /// The form to use for a header that arrives as a standalone blob — an ancestor supplied in an
    /// execution witness, say — because its hash is `keccak256` of exactly those bytes: trailing
    /// bytes that decoding ignored would still be hashed, so a lenient decode would pair a header
    /// with a hash that is not its own.
    ///
    /// # Errors
    /// [`rlp::DecoderError::RlpIsTooShort`] if the header declares a payload the buffer does not
    /// hold, [`rlp::DecoderError::RlpIsTooBig`] if bytes follow the header, and
    /// [`rlp::DecoderError::RlpInvalidLength`] if the declared length overflows a `usize`; otherwise
    /// whatever decoding the header itself reports.
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

    /// Check if the ommers hash equals to empty hash list.
    #[must_use]
    pub fn ommers_hash_is_empty(&self) -> bool {
        self.ommers_hash == EMPTY_OMMER_ROOT_HASH
    }

    /// Check if the transaction root equals to empty root.
    #[must_use]
    pub fn transaction_root_is_empty(&self) -> bool {
        self.transactions_root == EMPTY_ROOT_HASH
    }

    /// Returns the blob fee for _this_ block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None
    #[must_use]
    pub fn blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        blob_params.calc_blob_fee(self.excess_blob_gas?)
    }

    /// Returns the blob fee for the next block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None.
    ///
    /// See also [`Self::next_block_excess_blob_gas`]
    #[must_use]
    pub fn next_block_blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        blob_params.calc_blob_fee(self.next_block_excess_blob_gas(blob_params)?)
    }

    /// Calculate base fee for next block according to the EIP-1559 spec.
    ///
    /// Returns a `None` if no base fee is set, no EIP-1559 support
    #[must_use]
    pub fn next_block_base_fee(&self, base_fee_params: BaseFeeParams) -> Option<u64> {
        calc_next_block_base_fee(
            self.gas_used,
            self.gas_limit,
            self.base_fee_per_gas?,
            base_fee_params,
        )
    }

    /// Calculate excess blob gas for the next block according to the EIP-4844
    /// spec.
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

    /// Calculate a heuristic for the in-memory size of the [Header].
    #[must_use]
    pub const fn size(&self) -> usize {
        size_of::<Self>() + self.extra_data.len()
    }

    /// True if the shanghai hardfork is active.
    ///
    /// This function checks that the withdrawals root field is present.
    #[must_use]
    pub const fn shanghai_active(&self) -> bool {
        self.withdrawals_root.is_some()
    }

    /// True if the Cancun hardfork is active.
    ///
    /// This function checks that the blob gas used field is present.
    #[must_use]
    pub const fn cancun_active(&self) -> bool {
        self.blob_gas_used.is_some()
    }

    /// True if the Prague hardfork is active.
    ///
    /// This function checks that the requests hash is present.
    #[must_use]
    pub const fn prague_active(&self) -> bool {
        self.requests_hash.is_some()
    }

    /// True if the Amsterdam hardfork is active.
    ///
    /// This function checks that the block access list hash is present.
    #[must_use]
    pub const fn amsterdam_active(&self) -> bool {
        self.block_access_list_hash.is_some()
    }

    /// The first trailing field present while the one before it is absent, if any.
    ///
    /// The trailing fields are **positional** — the RLP carries no names, only a length, so item 15 is
    /// `base_fee_per_gas` and nothing else can be. A header with a gap therefore has no consensus
    /// encoding: writing it shifts every later field one place earlier, and reading those bytes back
    /// yields a *different* header. Since forks activate in order, real chains only ever produce a
    /// prefix, and decoding cannot produce anything else.
    ///
    /// The fork predicates above read the same shape — [`Self::shanghai_active`] answers from
    /// `withdrawals_root` alone — so a gap makes them disagree with one another too.
    #[must_use]
    pub fn first_trailing_field_gap(&self) -> Option<HeaderField> {
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
    /// The fallible counterpart of the [`rlp::Encodable`] impl, and the form to use for a header
    /// assembled field by field: every field is `pub`, so a gap in the trailing fields is
    /// constructible, and encoding a gap yields *another* header's bytes rather than a failure the
    /// `Encodable` trait is able to report. A header that came from decoding needs neither — it is a
    /// prefix by construction.
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

/// Total, and only for a header whose trailing fields form a prefix.
///
/// Nothing here can fail, so the trait fits: the mandatory fields are all fixed-width or
/// length-prefixed, and the trailing ones are written only when present. What the trait *cannot*
/// express is the one way a header has no encoding — a gap in those trailing fields, which this would
/// write as a shorter list that reads back as different fields. That is a returned error rather than an
/// assertion here, on [`Header::encode_rlp`].
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
        let items = crate::rlp_strict::checked_len(rlp)?;
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

    /// `encode_rlp` must accept exactly the prefixes, on all 256 shapes and not just the 9 real ones,
    /// and must name the first field that breaks one.
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
        // One shape per fork boundary from Frontier to the last field, and no others.
        assert_eq!(prefixes, 9);
    }

    /// Positional fields round-trip only as a prefix, so every prefix must round-trip exactly — the
    /// item count alone has to identify which fields are present.
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

    /// Why the gap has to be refused rather than encoded, spelled out on the bytes.
    ///
    /// `{blob_gas_used: Some(x)}` with the two fields before it absent writes 16 items, and item 15 is
    /// `base_fee_per_gas` by position — so `x` reads back as a base fee and `blob_gas_used` reads back
    /// as absent. Nothing about those bytes is malformed; they are a valid London header that says
    /// something else. Two distinct headers therefore share one encoding and one hash, which is exactly
    /// what a block hash must never allow.
    ///
    /// Some gaps are caught by accident, because the field a value shifts into is a different width —
    /// a 32-byte withdrawals root does not fit the `u64` `base_fee_per_gas`. This one shifts a `u64`
    /// into a `u64`, so nothing catches it but the check.
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
