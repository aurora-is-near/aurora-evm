//! Merkle-Patricia trie lookups and secure-key updates over witness nodes.
//!
//! [`NodeStore`] indexes RLP nodes by Keccak-256 and follows hashed or embedded children.
//! Lookups borrow values without allocation; validated field offsets avoid rescanning branches.
//! [`PatchTrie`] updates revealed paths while retaining references to untouched subtrees.
//!
//! Node formats follow the [Yellow Paper], Appendices B–D. See the
//! [lookup algorithm and trust boundary](crate#sparse-witness-lookups) for implementation details.
//!
//! [Yellow Paper]: https://ethereum.github.io/yellowpaper/paper.pdf

use crate::crypto::keccak256;
use crate::sparse::decode::{Child, Decoded, Malformed, Node};

mod decode;
mod patch;
mod sort;
pub use patch::{PatchError, PatchTrie};
#[cfg(any(test, feature = "test-utils"))]
mod tests;
#[cfg(feature = "test-utils")]
pub use tests::reference;

/// Witness RLP nodes indexed by Keccak-256.
#[derive(Clone, Debug, Default)]
pub struct NodeStore {
    nodes: Vec<Entry>,
}

/// Indexed bytes and validated field offsets; malformed unused nodes remain inert.
#[derive(Clone, Debug)]
struct Entry {
    hash: [u8; 32],
    bytes: Vec<u8>,
    decoded: Result<Decoded, Malformed>,
}

impl NodeStore {
    /// Indexes nodes by Keccak-256 and caches decoding results without copying their bytes.
    #[must_use]
    pub fn new<I: IntoIterator<Item = Vec<u8>>>(nodes: I) -> Self {
        let mut nodes: Vec<_> = nodes
            .into_iter()
            .map(|bytes| Entry {
                hash: keccak256(&bytes),
                decoded: Decoded::decode(&bytes),
                bytes,
            })
            .collect();
        sort::by_hash(&mut nodes);
        nodes.dedup_by_key(|entry| entry.hash);
        Self { nodes }
    }

    /// Number of distinct nodes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the store holds no nodes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether a node with this hash was revealed.
    #[must_use]
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.nodes
            .binary_search_by_key(hash, |entry| entry.hash)
            .is_ok()
    }

    /// Returns the value at `key`, or `None` for proven absence, under trusted `root`.
    ///
    /// `key` is the path in bytes, already hashed for secure tries.
    ///
    /// # Errors
    /// [`LookupError::BlindedNode`] for missing nodes; [`LookupError::MalformedNode`] for
    /// invalid node data encountered on the path.
    pub fn get(&self, root: [u8; 32], key: &[u8]) -> Result<Option<&[u8]>, LookupError> {
        if root == crate::EMPTY_ROOT_HASH {
            return Ok(None);
        }
        let path = Nibbles::new(key);
        let mut position = 0;
        let mut hash = root;
        let (mut bytes, mut decoded) = self.node(&hash, true)?;
        let mut require_branch = false;
        loop {
            let malformed = LookupError::MalformedNode(hash);
            let node = decoded.view(bytes);
            if require_branch && !matches!(node, Node::Branch(_)) {
                return Err(malformed);
            }
            require_branch = false;
            let child = match node {
                Node::Leaf {
                    path: leaf_path,
                    value,
                } => {
                    return Ok((path.suffix(position) == leaf_path).then_some(value));
                }
                Node::Extension {
                    path: prefix,
                    child,
                } => {
                    if !path.suffix(position).starts_with(&prefix) {
                        return Ok(None);
                    }
                    position += prefix.len();
                    require_branch = true;
                    child
                }
                Node::Branch(branch) => {
                    let Some(nibble) = path.nibble(position) else {
                        return Ok(branch.value());
                    };
                    let Some(child) = branch.child(nibble) else {
                        return Ok(None);
                    };
                    position += 1;
                    child
                }
            };
            (bytes, decoded) = match child {
                Child::Hash(next) => {
                    hash = next;
                    self.node(&hash, false)?
                }
                Child::Embedded(raw) => (raw, Decoded::decode(raw).map_err(|_| malformed)?),
            };
        }
    }

    /// Resolves a hashed node; only roots may hash an encoding shorter than 32 bytes.
    fn node(&self, hash: &[u8; 32], root: bool) -> Result<(&[u8], Decoded), LookupError> {
        let index = self
            .nodes
            .binary_search_by_key(hash, |entry| entry.hash)
            .map_err(|_| LookupError::BlindedNode(*hash))?;
        let entry = &self.nodes[index];
        if !root && entry.bytes.len() < 32 {
            return Err(LookupError::MalformedNode(*hash));
        }
        let decoded = entry
            .decoded
            .map_err(|_| LookupError::MalformedNode(*hash))?;
        Ok((&entry.bytes, decoded))
    }
}

/// A key viewed as a sequence of nibbles.
#[derive(Clone, Copy)]
struct Nibbles<'a> {
    key: &'a [u8],
}

impl<'a> Nibbles<'a> {
    const fn new(key: &'a [u8]) -> Self {
        Self { key }
    }

    fn nibble(&self, index: usize) -> Option<u8> {
        let byte = *self.key.get(index / 2)?;
        Some(if index.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0x0f
        })
    }

    /// The path suffix starting at nibble `start`.
    const fn suffix(&self, start: usize) -> Path<'a> {
        Path {
            key: self.key,
            start,
        }
    }
}

/// A nibble sequence: either a suffix of a key or a decoded hex-prefix path.
#[derive(Clone, Copy)]
struct Path<'a> {
    key: &'a [u8],
    /// Nibble offset into `key`.
    start: usize,
}

impl Path<'_> {
    const fn len(&self) -> usize {
        (2 * self.key.len()).saturating_sub(self.start)
    }

    fn nibble(&self, index: usize) -> Option<u8> {
        Nibbles::new(self.key).nibble(self.start + index)
    }

    fn starts_with(&self, prefix: &Self) -> bool {
        prefix.len() <= self.len()
            && (0..prefix.len()).all(|index| self.nibble(index) == prefix.nibble(index))
    }
}

impl PartialEq for Path<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.starts_with(other)
    }
}

/// Why a lookup could not be answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    /// A required node is unrevealed; only its hash is known.
    BlindedNode([u8; 32]),
    /// A node reached through a trusted hash is not a valid trie node.
    MalformedNode([u8; 32]),
}
