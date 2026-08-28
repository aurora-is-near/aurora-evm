//! Verification of ancestor headers revealed by an execution witness.
//!
//! [`derive_ancestors`] exact-decodes a contiguous chain ending at the current block's parent and
//! returns that parent with the verified `BLOCKHASH` window.

use crate::block::header::Header;
use crate::block::sealed::SealedHeader;
use crate::constants::BLOCKHASH_WINDOW;
use crate::crypto::keccak256;
use core::fmt;
use primitive_types::H256;
use std::collections::BTreeMap;

/// Why a claimed ancestor chain is not one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AncestorChainError {
    /// An entry is not exactly one valid RLP header.
    Decode {
        /// Position in the supplied witness list.
        index: usize,
        /// Header decoding error.
        source: rlp::DecoderError,
    },
    /// No parent header was supplied.
    MissingParent,
    /// The witness exceeds the `BLOCKHASH` window.
    LimitExceeded {
        /// Supplied header count.
        count: usize,
        /// Maximum accepted count.
        limit: usize,
    },
    /// A child's `parent_hash` does not match the supplied parent.
    ParentHashMismatch {
        /// Child block number.
        child_number: u64,
        /// Supplied parent block number.
        parent_number: u64,
        /// Hash committed to by the child.
        expected_parent_hash: H256,
        /// Actual hash of the supplied parent.
        actual_parent_hash: H256,
    },
    /// Adjacent headers have non-contiguous block numbers.
    NumberNotContiguous {
        /// Child block number.
        child_number: u64,
        /// Supplied parent block number.
        parent_number: u64,
    },
}

impl fmt::Display for AncestorChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { index, source } => {
                write!(f, "ancestor header at index {index} is malformed: {source}")
            }
            Self::MissingParent => write!(f, "the block's parent header is missing"),
            Self::LimitExceeded { count, limit } => {
                write!(
                    f,
                    "{count} ancestor headers supplied, at most {limit} usable"
                )
            }
            Self::ParentHashMismatch {
                child_number,
                parent_number,
                expected_parent_hash,
                actual_parent_hash,
            } => write!(
                f,
                "block {child_number} names parent {expected_parent_hash:?} but header {parent_number} hashes to {actual_parent_hash:?}"
            ),
            Self::NumberNotContiguous {
                child_number,
                parent_number,
            } => {
                write!(
                    f,
                    "block {child_number} cannot follow block {parent_number}"
                )
            }
        }
    }
}

impl core::error::Error for AncestorChainError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A verified parent and its `BLOCKHASH` ancestor window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ancestors {
    parent: SealedHeader,
    hashes: BTreeMap<u64, H256>,
}

impl Ancestors {
    /// The current block's parent.
    #[must_use]
    pub const fn parent(&self) -> &SealedHeader {
        &self.parent
    }

    /// The pre-state root this block executes from.
    #[must_use]
    pub const fn pre_state_root(&self) -> H256 {
        self.parent.header().state_root
    }

    /// Verified ancestor hashes keyed by block number.
    #[must_use]
    pub const fn hashes(&self) -> &BTreeMap<u64, H256> {
        &self.hashes
    }

    /// Splits the parent from the `BLOCKHASH` window.
    #[must_use]
    pub fn split(self) -> (SealedHeader, BTreeMap<u64, H256>) {
        (self.parent, self.hashes)
    }
}

/// Verifies raw ancestor headers, in any order, as a chain ending at `current_header`'s parent.
///
/// # Errors
/// [`AncestorChainError`] if the parent is missing, the window is too large, an entry is malformed,
/// or adjacent hashes or block numbers do not match.
pub fn derive_ancestors(
    current_header: &Header,
    encoded_headers: &[Vec<u8>],
) -> Result<Ancestors, AncestorChainError> {
    validate_ancestor_count(encoded_headers.len())?;

    let mut ancestor_headers = decode_ancestor_headers(encoded_headers)?;
    ancestor_headers.sort_by_key(|header| header.header().number);
    let ancestor_hashes = verify_and_collect_ancestor_hashes(current_header, &ancestor_headers)?;
    let parent = ancestor_headers
        .pop()
        .ok_or(AncestorChainError::MissingParent)?;

    Ok(Ancestors {
        parent,
        hashes: ancestor_hashes,
    })
}

/// Rejects a missing parent or a witness larger than the `BLOCKHASH` window.
const fn validate_ancestor_count(count: usize) -> Result<(), AncestorChainError> {
    if count == 0 {
        return Err(AncestorChainError::MissingParent);
    }
    if count > BLOCKHASH_WINDOW {
        return Err(AncestorChainError::LimitExceeded {
            count,
            limit: BLOCKHASH_WINDOW,
        });
    }
    Ok(())
}

/// Exact-decodes headers while preserving the hash of their supplied bytes.
fn decode_ancestor_headers(
    encoded_headers: &[Vec<u8>],
) -> Result<Vec<SealedHeader>, AncestorChainError> {
    encoded_headers
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            Header::decode_exact(bytes)
                .map(|header| SealedHeader::new_unchecked(header, keccak256(bytes)))
                .map_err(|source| AncestorChainError::Decode { index, source })
        })
        .collect()
}

/// Verifies the chain backwards and collects each verified parent hash.
fn verify_and_collect_ancestor_hashes(
    current_header: &Header,
    ancestor_headers: &[SealedHeader],
) -> Result<BTreeMap<u64, H256>, AncestorChainError> {
    let mut ancestor_hashes = BTreeMap::new();
    let mut child_header = current_header;

    for sealed_parent_header in ancestor_headers.iter().rev() {
        let parent_header = sealed_parent_header.header();
        let actual_parent_hash = sealed_parent_header.hash();

        if child_header.parent_hash != actual_parent_hash {
            return Err(AncestorChainError::ParentHashMismatch {
                child_number: child_header.number,
                parent_number: parent_header.number,
                expected_parent_hash: child_header.parent_hash,
                actual_parent_hash,
            });
        }
        if parent_header.number.checked_add(1) != Some(child_header.number) {
            return Err(AncestorChainError::NumberNotContiguous {
                child_number: child_header.number,
                parent_number: parent_header.number,
            });
        }

        ancestor_hashes.insert(parent_header.number, actual_parent_hash);
        child_header = parent_header;
    }

    Ok(ancestor_hashes)
}

#[cfg(test)]
mod tests {
    use super::{AncestorChainError, Ancestors, derive_ancestors};
    use crate::block::header::Header;
    use crate::constants::BLOCKHASH_WINDOW;
    use crate::crypto::keccak256;
    use primitive_types::H256;

    /// Builds `len` linked ancestor headers and their child, returning ancestors as raw RLP.
    fn chain(len: usize) -> (Header, Vec<Vec<u8>>) {
        let mut raw = Vec::new();
        let mut previous = H256::zero();
        for number in 1..=len {
            let number = u64::try_from(number).expect("test chain length fits in u64");
            let header = Header {
                number,
                parent_hash: previous,
                // Distinguishable state roots, so the parent's can be identified.
                state_root: H256::from_low_u64_be(number),
                ..Header::default()
            };
            let bytes = rlp::encode(&header).to_vec();
            previous = header.hash_slow();
            raw.push(bytes);
        }
        let child = Header {
            number: u64::try_from(len).expect("test chain length fits in u64") + 1,
            parent_hash: previous,
            ..Header::default()
        };
        (child, raw)
    }

    #[test]
    fn a_genuine_chain_yields_its_parent_and_window() {
        let (child, raw) = chain(3);
        let ancestors = derive_ancestors(&child, &raw).unwrap();

        assert_eq!(ancestors.parent().header().number, 3);
        assert_eq!(ancestors.pre_state_root(), H256::from_low_u64_be(3));
        assert_eq!(ancestors.hashes().len(), 3);
        assert_eq!(
            ancestors.hashes().keys().copied().collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        for (index, bytes) in raw.iter().enumerate() {
            let number = u64::try_from(index + 1).unwrap();
            assert_eq!(ancestors.hashes()[&number], keccak256(bytes));
        }
    }

    /// The order they arrive in must not matter — only the links.
    #[test]
    fn order_of_arrival_is_irrelevant() {
        let (child, mut raw) = chain(4);
        let expected = derive_ancestors(&child, &raw).unwrap();
        raw.reverse();
        assert_eq!(derive_ancestors(&child, &raw).unwrap(), expected);
        raw.swap(0, 2);
        assert_eq!(derive_ancestors(&child, &raw).unwrap(), expected);
    }

    #[test]
    fn a_broken_link_is_rejected() {
        let (child, mut raw) = chain(3);
        // Alter the middle ancestor, so the one after it no longer names it.
        let mut tampered: Header = rlp::decode(&raw[1]).unwrap();
        tampered.gas_limit += 1;
        raw[1] = rlp::encode(&tampered).to_vec();

        assert!(matches!(
            derive_ancestors(&child, &raw),
            Err(AncestorChainError::ParentHashMismatch {
                child_number: 3,
                parent_number: 2,
                ..
            })
        ));
    }

    #[test]
    fn a_substituted_parent_is_rejected() {
        let (child, mut raw) = chain(2);
        // Replace the parent with an unrelated header at the same number.
        raw[1] = rlp::encode(&Header {
            number: 2,
            parent_hash: H256::repeat_byte(0xee),
            state_root: H256::repeat_byte(0xff),
            ..Header::default()
        })
        .to_vec();

        assert!(matches!(
            derive_ancestors(&child, &raw),
            Err(AncestorChainError::ParentHashMismatch {
                child_number: 3,
                parent_number: 2,
                ..
            })
        ));
    }

    /// A missing link is detected by its child's `parent_hash`.
    #[test]
    fn a_gap_in_the_chain_is_rejected() {
        let (child, raw) = chain(3);
        let punctured = vec![raw[0].clone(), raw[2].clone()];
        assert!(matches!(
            derive_ancestors(&child, &punctured),
            Err(AncestorChainError::ParentHashMismatch {
                child_number: 3,
                parent_number: 1,
                ..
            })
        ));
    }

    #[test]
    fn a_repeated_ancestor_is_rejected() {
        let (child, mut raw) = chain(3);
        raw[0] = raw[2].clone();
        assert!(matches!(
            derive_ancestors(&child, &raw),
            Err(AncestorChainError::ParentHashMismatch { .. })
        ));
    }

    /// A valid hash link may still claim a non-contiguous block number.
    #[test]
    fn a_parent_claiming_the_wrong_number_is_rejected() {
        let liar = Header {
            number: 5,
            state_root: H256::repeat_byte(0x55),
            ..Header::default()
        };
        let raw = vec![rlp::encode(&liar).to_vec()];
        let child = Header {
            number: 10,
            parent_hash: liar.hash_slow(),
            ..Header::default()
        };
        assert!(matches!(
            derive_ancestors(&child, &raw),
            Err(AncestorChainError::NumberNotContiguous {
                child_number: 10,
                parent_number: 5
            })
        ));
    }

    #[test]
    fn no_ancestors_means_no_pre_state_root() {
        let (child, _) = chain(1);
        assert_eq!(
            derive_ancestors(&child, &[]).unwrap_err(),
            AncestorChainError::MissingParent
        );
    }

    #[test]
    fn limit_is_checked_before_header_decoding() {
        let (child, _) = chain(1);
        let malformed = vec![Vec::new(); BLOCKHASH_WINDOW + 1];
        assert_eq!(
            derive_ancestors(&child, &malformed).unwrap_err(),
            AncestorChainError::LimitExceeded {
                count: BLOCKHASH_WINDOW + 1,
                limit: BLOCKHASH_WINDOW,
            }
        );
    }

    #[test]
    fn more_ancestors_than_blockhash_can_reach_are_rejected() {
        let (child, raw) = chain(BLOCKHASH_WINDOW + 1);
        assert!(matches!(
            derive_ancestors(&child, &raw),
            Err(AncestorChainError::LimitExceeded {
                limit: BLOCKHASH_WINDOW,
                ..
            })
        ));
        // Exactly the limit is fine.
        let (child, raw) = chain(BLOCKHASH_WINDOW);
        assert!(derive_ancestors(&child, &raw).is_ok());
    }

    /// Padding must not change the bytes hashed for an otherwise accepted ancestor.
    #[test]
    fn padded_ancestor_bytes_are_rejected() {
        let (child, mut raw) = chain(2);
        raw[1].push(0x00);
        assert!(matches!(
            derive_ancestors(&child, &raw),
            Err(AncestorChainError::Decode { index: 1, .. })
        ));
    }

    #[test]
    fn maximum_parent_number_is_rejected_without_overflow() {
        let parent = Header {
            number: u64::MAX,
            ..Header::default()
        };
        let raw = vec![rlp::encode(&parent).to_vec()];
        let child = Header {
            number: u64::MAX,
            parent_hash: parent.hash_slow(),
            ..Header::default()
        };

        assert_eq!(
            derive_ancestors(&child, &raw).unwrap_err(),
            AncestorChainError::NumberNotContiguous {
                child_number: u64::MAX,
                parent_number: u64::MAX,
            }
        );
    }

    #[test]
    fn split_returns_the_same_values_the_accessors_do() {
        let (child, raw) = chain(2);
        let ancestors: Ancestors = derive_ancestors(&child, &raw).unwrap();
        let parent_number = ancestors.parent().header().number;
        let window = ancestors.hashes().clone();
        let (parent, hashes) = ancestors.split();
        assert_eq!(parent.header().number, parent_number);
        assert_eq!(hashes, window);
    }
}
