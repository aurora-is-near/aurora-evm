//! Strict RLP and MPT decoding with compact offsets for allocation-free lookups.

use super::Path;

/// Invalid RLP or noncanonical trie structure.
#[derive(Clone, Copy, Debug)]
pub(super) struct Malformed;

/// Validated offsets into one immutable RLP node.
#[derive(Clone, Copy, Debug)]
pub(super) enum Decoded {
    Leaf {
        path_start: usize,
        path_end: usize,
        value_start: usize,
    },
    Extension {
        path_start: usize,
        path_end: usize,
        child_start: usize,
    },
    Branch {
        starts: [u16; 17],
        value_start: usize,
    },
}

/// A validated child reference.
#[derive(Clone, Copy)]
pub(super) enum Child<'a> {
    Hash([u8; 32]),
    Embedded(&'a [u8]),
}

/// Borrowed fields of a validated trie node.
pub(super) enum Node<'a> {
    Leaf { path: Path<'a>, value: &'a [u8] },
    Extension { path: Path<'a>, child: Child<'a> },
    Branch(Branch<'a>),
}

/// A branch whose child offsets were checked during construction.
pub(super) struct Branch<'a> {
    bytes: &'a [u8],
    starts: [u16; 17],
    value_start: usize,
}

impl<'a> Branch<'a> {
    /// Selects a child without scanning preceding RLP items.
    pub(super) fn child(&self, nibble: u8) -> Option<Child<'a>> {
        let i = usize::from(nibble);
        child_view(&self.bytes[usize::from(self.starts[i])..usize::from(self.starts[i + 1])])
    }

    /// Returns the terminal value, or proven absence for an empty value.
    pub(super) fn value(&self) -> Option<&'a [u8]> {
        let value = &self.bytes[self.value_start..];
        (!value.is_empty()).then_some(value)
    }
}

impl Decoded {
    /// Validates the complete node, including embedded descendants but not hashed subtrees.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        let mut rest = bytes;
        let list = take(&mut rest)?;
        if !list.list || !rest.is_empty() {
            return Err(Malformed);
        }
        let mut payload = list.payload;
        let mut items = [Item::EMPTY; 17];
        let mut count = 0;
        while !payload.is_empty() {
            let slot = items.get_mut(count).ok_or(Malformed)?;
            *slot = take(&mut payload)?;
            count += 1;
        }

        match count {
            2 => Self::short(bytes, &items[..2]),
            17 => Self::branch(bytes, &items),
            _ => Err(Malformed),
        }
    }

    /// Validates a leaf or a nonempty extension; extensions lead only to branches.
    fn short(bytes: &[u8], items: &[Item<'_>]) -> Result<Self, Malformed> {
        let [path, value] = items else {
            return Err(Malformed);
        };
        if path.list {
            return Err(Malformed);
        }
        let (&flag, _) = path.payload.split_first().ok_or(Malformed)?;
        if flag >> 4 > 3 || (flag & 0x10 == 0 && flag & 0x0f != 0) {
            return Err(Malformed);
        }
        let path_end = bytes.len() - value.raw.len();
        let path_start = path_end - path.payload.len();
        if flag & 0x20 != 0 {
            if value.list {
                return Err(Malformed);
            }

            Ok(Self::Leaf {
                path_start,
                path_end,
                value_start: bytes.len() - value.payload.len(),
            })
        } else {
            if path.payload == [0] {
                return Err(Malformed);
            }
            validate_child(*value, true)?;
            if value.raw == [0x80] {
                return Err(Malformed);
            }

            Ok(Self::Extension {
                path_start,
                path_end,
                child_start: path_end,
            })
        }
    }

    /// Validates child references, the terminal value, and canonical branch occupancy.
    fn branch(bytes: &[u8], items: &[Item<'_>; 17]) -> Result<Self, Malformed> {
        let mut starts = [0; 17];
        let mut offset = bytes.len() - items.iter().map(|item| item.raw.len()).sum::<usize>();
        let mut occupied = 0;
        for (i, item) in items.iter().enumerate() {
            // Sixteen references occupy at most 16 * 33 bytes, plus the list header.
            starts[i] = u16::try_from(offset).map_err(|_| Malformed)?;
            if i < 16 {
                validate_child(*item, false)?;
                occupied += usize::from(item.raw != [0x80]);
            } else {
                if item.list {
                    return Err(Malformed);
                }
                occupied += usize::from(!item.payload.is_empty());
            }
            offset += item.raw.len();
        }
        if occupied < 2 {
            return Err(Malformed);
        }

        Ok(Self::Branch {
            starts,
            value_start: bytes.len() - items[16].payload.len(),
        })
    }

    /// Borrows fields at previously validated offsets.
    pub(super) fn view(self, bytes: &[u8]) -> Node<'_> {
        match self {
            Self::Leaf {
                path_start,
                path_end,
                value_start,
            } => Node::Leaf {
                path: path_view(&bytes[path_start..path_end]),
                value: &bytes[value_start..],
            },
            Self::Extension {
                path_start,
                path_end,
                child_start,
            } => Node::Extension {
                path: path_view(&bytes[path_start..path_end]),
                child: nonempty_child_view(&bytes[child_start..]),
            },
            Self::Branch {
                starts,
                value_start,
            } => Node::Branch(Branch {
                bytes,
                starts,
                value_start,
            }),
        }
    }
}

/// Decodes the flags of an already validated compact path.
fn path_view(bytes: &[u8]) -> Path<'_> {
    Path {
        key: bytes,
        start: if bytes[0] & 0x10 != 0 { 1 } else { 2 },
    }
}

/// Borrows a validated child; hash references have the canonical prefix `0xa0`.
fn child_view(bytes: &[u8]) -> Option<Child<'_>> {
    (bytes[0] != 0x80).then(|| nonempty_child_view(bytes))
}

/// Borrows a child already proven nonempty during decoding.
fn nonempty_child_view(bytes: &[u8]) -> Child<'_> {
    if bytes[0] == 0xa0 {
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[1..]);
        Child::Hash(hash)
    } else {
        Child::Embedded(bytes)
    }
}

/// Validates inline nodes recursively; each is under 32 bytes, bounding recursion depth.
fn validate_child(item: Item<'_>, require_branch: bool) -> Result<(), Malformed> {
    if item.list {
        if item.raw.len() >= 32 {
            return Err(Malformed);
        }
        let decoded = Decoded::decode(item.raw)?;
        if require_branch && !matches!(decoded, Decoded::Branch { .. }) {
            return Err(Malformed);
        }
    } else if !matches!(item.payload.len(), 0 | 32) {
        return Err(Malformed);
    }

    Ok(())
}

/// One canonically encoded RLP item, borrowed from its parent.
#[derive(Clone, Copy)]
struct Item<'a> {
    raw: &'a [u8],
    payload: &'a [u8],
    list: bool,
}

impl Item<'_> {
    const EMPTY: Self = Self {
        raw: &[],
        payload: &[],
        list: false,
    };
}

/// Consumes exactly one canonical RLP item, checking lengths before slicing.
fn take<'a>(input: &mut &'a [u8]) -> Result<Item<'a>, Malformed> {
    let bytes = *input;
    let (&prefix, _) = bytes.split_first().ok_or(Malformed)?;
    let list = prefix >= 0xc0;
    let (header, length) = match prefix {
        0..=0x7f => (0, 1),
        0x80..=0xb7 => (1, usize::from(prefix - 0x80)),
        0xc0..=0xf7 => (1, usize::from(prefix - 0xc0)),
        _ => {
            let width = usize::from(if list { prefix - 0xf7 } else { prefix - 0xb7 });
            let encoded = bytes.get(1..=width).ok_or(Malformed)?;
            if encoded[0] == 0 {
                return Err(Malformed);
            }
            let length = encoded
                .iter()
                .try_fold(0usize, |length, byte| {
                    length.checked_mul(256)?.checked_add(usize::from(*byte))
                })
                .ok_or(Malformed)?;
            if length < 56 {
                return Err(Malformed);
            }
            (1 + width, length)
        }
    };
    let total = header.checked_add(length).ok_or(Malformed)?;
    let raw = bytes.get(..total).ok_or(Malformed)?;
    let payload = &raw[header..];
    if prefix == 0x81 && payload[0] < 0x80 {
        return Err(Malformed);
    }
    *input = &bytes[total..];

    Ok(Item { raw, payload, list })
}
