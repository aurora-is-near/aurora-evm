//! Frozen pre-refactor sparse lookup (2026-09-18), for performance comparison only.
//! This intentionally retains the old permissive parser; never use it to validate input.

use super::keccak256;
use std::collections::BTreeMap;

/// Why a lookup could not be answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    /// A required node is unrevealed; only its hash is known.
    BlindedNode([u8; 32]),
    /// A node reached through a trusted hash is not a valid trie node.
    MalformedNode([u8; 32]),
}

/// Witness RLP nodes indexed by Keccak-256.
#[derive(Clone, Debug, Default)]
pub struct NodeStore {
    nodes: BTreeMap<[u8; 32], Vec<u8>>,
}

impl NodeStore {
    /// Indexes `nodes` by `keccak256(node)`.
    #[must_use]
    pub fn new<I: IntoIterator<Item = Vec<u8>>>(nodes: I) -> Self {
        Self {
            nodes: nodes
                .into_iter()
                .map(|node| (keccak256(&node), node))
                .collect(),
        }
    }

    /// Number of distinct nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the store holds no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether a node with this hash was revealed.
    #[must_use]
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Returns the value at `key`, or `None` for proven absence, under trusted `root`.
    ///
    /// `key` is the path in bytes, already hashed for secure tries.
    ///
    /// # Errors
    /// [`LookupError::BlindedNode`] for missing nodes; [`LookupError::MalformedNode`] for
    /// invalid node data encountered on the path.
    pub fn get(&self, root: [u8; 32], key: &[u8]) -> Result<Option<&[u8]>, LookupError> {
        if root == alloy_trie::EMPTY_ROOT_HASH.0 {
            return Ok(None);
        }
        let path = Nibbles::new(key);
        let mut position = 0;
        let mut hash = root;
        let mut bytes = self.node(&hash)?;
        loop {
            let malformed = LookupError::MalformedNode(hash);
            let child = match Node::decode(bytes).map_err(|_| malformed)? {
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
                    child
                }
                Node::Branch(branch) => {
                    let Some(nibble) = path.nibble(position) else {
                        return branch.value().map_err(|_| malformed);
                    };
                    let Some(child) = branch.child(nibble).map_err(|_| malformed)? else {
                        return Ok(None);
                    };
                    position += 1;
                    child
                }
            };
            bytes = match child {
                Child::Hash(next) => {
                    hash = next;
                    self.node(&hash)?
                }
                Child::Embedded(raw) => raw,
            };
        }
    }

    fn node(&self, hash: &[u8; 32]) -> Result<&[u8], LookupError> {
        self.nodes
            .get(hash)
            .map(Vec::as_slice)
            .ok_or(LookupError::BlindedNode(*hash))
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

/// Invalid trie-node encoding.
struct Malformed;

/// A reference from a node to its child.
#[derive(Clone, Copy)]
enum Child<'a> {
    Hash([u8; 32]),
    /// A node shorter than 32 bytes, stored inline as its raw RLP.
    Embedded(&'a [u8]),
}

/// A branch node whose slots are decoded on demand.
struct Branch<'a> {
    rlp: rlp::Rlp<'a>,
}

impl<'a> Branch<'a> {
    fn child(&self, nibble: u8) -> Result<Option<Child<'a>>, Malformed> {
        decode_child(&self.rlp.at(usize::from(nibble)).map_err(|_| Malformed)?)
    }

    fn value(&self) -> Result<Option<&'a [u8]>, Malformed> {
        let item = self.rlp.at(16).map_err(|_| Malformed)?;
        if !item.is_data() {
            return Err(Malformed);
        }
        let value = item.data().map_err(|_| Malformed)?;
        Ok((!value.is_empty()).then_some(value))
    }
}

enum Node<'a> {
    Leaf { path: Path<'a>, value: &'a [u8] },
    Extension { path: Path<'a>, child: Child<'a> },
    Branch(Branch<'a>),
}

impl<'a> Node<'a> {
    /// Decodes a node and its path; branch slots remain lazy.
    fn decode(bytes: &'a [u8]) -> Result<Self, Malformed> {
        let rlp = rlp::Rlp::new(bytes);
        if !rlp.is_list() {
            return Err(Malformed);
        }
        match rlp.item_count().map_err(|_| Malformed)? {
            2 => {
                let encoded = rlp
                    .at(0)
                    .and_then(|item| item.data())
                    .map_err(|_| Malformed)?;
                let (leaf, path) = decode_hex_prefix(encoded)?;
                let item = rlp.at(1).map_err(|_| Malformed)?;
                if leaf {
                    Ok(Self::Leaf {
                        path,
                        value: item.data().map_err(|_| Malformed)?,
                    })
                } else {
                    let child = decode_child(&item)?.ok_or(Malformed)?;
                    Ok(Self::Extension { path, child })
                }
            }
            17 => Ok(Self::Branch(Branch { rlp })),
            _ => Err(Malformed),
        }
    }
}

/// Decodes a child slot: `None` for an empty slot.
fn decode_child<'a>(item: &rlp::Rlp<'a>) -> Result<Option<Child<'a>>, Malformed> {
    if item.is_list() {
        return Ok(Some(Child::Embedded(item.as_raw())));
    }
    let data = item.data().map_err(|_| Malformed)?;
    match data.len() {
        0 => Ok(None),
        32 => data
            .try_into()
            .map(|hash| Some(Child::Hash(hash)))
            .map_err(|_| Malformed),
        _ => Err(Malformed),
    }
}

/// Decodes a hex-prefix encoded path into its leaf flag and nibbles.
fn decode_hex_prefix(encoded: &[u8]) -> Result<(bool, Path<'_>), Malformed> {
    let (&first, _) = encoded.split_first().ok_or(Malformed)?;
    let flags = first >> 4;
    if flags > 3 {
        return Err(Malformed);
    }
    let leaf = flags & 0x2 != 0;
    let odd = flags & 0x1 != 0;
    if !odd && first & 0x0f != 0 {
        return Err(Malformed);
    }
    Ok((
        leaf,
        Path {
            key: encoded,
            start: if odd { 1 } else { 2 },
        },
    ))
}
