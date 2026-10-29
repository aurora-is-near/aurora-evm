//! Mutable secure-trie overlay with lazy witness resolution and cached child commitments.

use super::decode::{Child, Decoded, Node};
use super::{LookupError, NodeStore, Path};
use crate::{EMPTY_ROOT_HASH, crypto::keccak256};
use core::fmt;

#[cfg(test)]
mod tests;

/// Updates a trusted witness root using already-hashed, 32-byte keys.
///
/// Only touched paths are materialized. Witness values are borrowed; new values and nodes use
/// reusable arenas. Apply upserts before removals when consuming canonical reth witnesses.
/// Every update error is sticky: neither updates nor finalization succeed until [`Self::reset`].
pub struct PatchTrie<'store> {
    store: &'store NodeStore,
    root: Link<'store>,
    nodes: Vec<Owned<'store>>,
    branches: Vec<[Link<'store>; 16]>,
    values: Vec<u8>,
    scratch: rlp::RlpStream,
    failure: Option<PatchError>,
    #[cfg(test)]
    hashes: usize,
}

/// A failed update; the overlay cannot be finalized until reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchError {
    /// A required witness node is missing or malformed.
    Node(LookupError),
    /// Empty values are not leaves; use [`PatchTrie::remove`] instead.
    EmptyValue,
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(LookupError::BlindedNode(hash)) => {
                write!(f, "unrevealed trie node {hash:02x?}")
            }
            Self::Node(LookupError::MalformedNode(hash)) => {
                write!(f, "malformed trie node {hash:02x?}")
            }
            Self::EmptyValue => f.write_str("empty trie value; use remove instead"),
        }
    }
}

impl std::error::Error for PatchError {}

/// Unresolved witness reference or index into the overlay arena.
#[derive(Clone, Copy)]
enum Link<'a> {
    Empty,
    Hash([u8; 32]),
    Embedded(&'a [u8]),
    Owned(usize),
}

/// Canonical child reference, cached independently of the encoding scratch.
#[derive(Clone, Copy)]
enum Reference {
    Empty,
    Hash([u8; 32]),
    Inline { bytes: [u8; 31], len: u8 },
}

impl Reference {
    fn append(self, stream: &mut rlp::RlpStream) {
        match self {
            Self::Empty => {
                stream.append_empty_data();
            }
            Self::Hash(hash) => {
                stream.append(&hash.as_slice());
            }
            Self::Inline { bytes, len } => {
                stream.append_raw(&bytes[..usize::from(len)], 1);
            }
        }
    }

    /// Copies only a child encoding already known to be shorter than 32 bytes.
    fn inline(raw: &[u8]) -> Self {
        let mut bytes = [0; 31];
        bytes[..raw.len()].copy_from_slice(raw);
        Self::Inline {
            bytes,
            len: raw.len().to_le_bytes()[0],
        }
    }
}

/// A compact nibble path; slicing changes offsets without allocation or repacking.
#[derive(Clone, Copy)]
struct Prefix {
    bytes: [u8; 32],
    start: u8,
    len: u8,
}

impl Prefix {
    const fn key(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            start: 0,
            len: 64,
        }
    }

    /// Packs a decoded path after `witness_node` checks its length against the remaining key.
    fn from_path(path: Path<'_>) -> Self {
        let mut prefix = Self::key([0; 32]);
        prefix.len = path.len().to_le_bytes()[0];
        for index in 0..prefix.len {
            // The caller checked the path length, and indices are strictly inside it.
            let position = path.start + usize::from(index);
            let byte = path.key[position / 2];
            let nibble = if position.is_multiple_of(2) {
                byte >> 4
            } else {
                byte & 15
            };
            prefix.set(index, nibble);
        }
        prefix
    }

    fn nibble(self, index: u8) -> u8 {
        let position = self.start + index;
        let byte = self.bytes[usize::from(position / 2)];
        if position.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 15
        }
    }

    fn set(&mut self, index: u8, nibble: u8) {
        let byte = &mut self.bytes[usize::from(index / 2)];
        if index.is_multiple_of(2) {
            *byte = (*byte & 15) | (nibble << 4);
        } else {
            *byte = (*byte & 0xf0) | nibble;
        }
    }

    const fn suffix(self, skip: u8) -> Self {
        Self {
            start: self.start + skip,
            len: self.len - skip,
            ..self
        }
    }

    const fn take(self, len: u8) -> Self {
        Self { len, ..self }
    }

    fn common(self, other: Self) -> u8 {
        (0..self.len.min(other.len))
            .take_while(|&index| self.nibble(index) == other.nibble(index))
            .count()
            .to_le_bytes()[0]
    }

    fn join(self, other: Self) -> Self {
        let mut joined = Self::key([0; 32]);
        joined.len = self.len + other.len;
        for index in 0..self.len {
            joined.set(index, self.nibble(index));
        }
        for index in 0..other.len {
            joined.set(self.len + index, other.nibble(index));
        }
        joined
    }

    /// Hex-prefix encoding (Yellow Paper Appendix D), at most 33 bytes for a secure key.
    fn encode(self, leaf: bool, out: &mut [u8; 33]) -> usize {
        let odd = self.len % 2;
        out[0] = u8::from(leaf) * 0x20 + odd * 0x10;
        if odd != 0 {
            out[0] |= self.nibble(0);
        }
        let mut index = odd;
        let mut used = 1;
        while index < self.len {
            out[used] = self.nibble(index) << 4 | self.nibble(index + 1);
            index += 2;
            used += 1;
        }
        used
    }
}

#[derive(Clone, Copy)]
enum Value<'a> {
    Borrowed(&'a [u8]),
    Arena { start: usize, len: usize },
}

#[derive(Clone, Copy)]
enum Kind<'a> {
    Leaf { path: Prefix, value: Value<'a> },
    Extension { path: Prefix, child: Link<'a> },
    Branch(usize),
}

#[derive(Clone, Copy)]
struct Owned<'a> {
    kind: Kind<'a>,
    cached: Option<Reference>,
    /// Nearest witness hash, retained for errors in embedded descendants.
    origin: [u8; 32],
}

impl<'store> PatchTrie<'store> {
    /// Starts an overlay without resolving `root`; the caller must authenticate it.
    #[must_use]
    pub fn new(store: &'store NodeStore, root: [u8; 32]) -> Self {
        Self {
            store,
            root: root_link(root),
            nodes: Vec::new(),
            branches: Vec::new(),
            values: Vec::new(),
            scratch: rlp::RlpStream::new(),
            failure: None,
            #[cfg(test)]
            hashes: 0,
        }
    }

    /// Discards changes and errors, retaining arena capacities for another root in the same store.
    pub fn reset(&mut self, root: [u8; 32]) {
        self.root = root_link(root);
        self.nodes.clear();
        self.branches.clear();
        self.values.clear();
        self.scratch.clear();
        self.failure = None;
        #[cfg(test)]
        {
            self.hashes = 0;
        }
    }

    /// Sets a nonempty value; returns whether the trie changed. Keys are not hashed again.
    ///
    /// The value is copied into the arena only if changed; witness values remain borrowed.
    /// # Errors
    /// [`PatchError`] for an empty value, an unproved path, or malformed nodes. Any error
    /// poisons this overlay until [`Self::reset`], including errors after partial mutation.
    pub fn insert(&mut self, key: &[u8; 32], value: &[u8]) -> Result<bool, PatchError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if value.is_empty() {
            self.failure = Some(PatchError::EmptyValue);
            return Err(PatchError::EmptyValue);
        }
        self.update(key, Some(value))
    }

    /// Removes a key, returning `false` for proven absence.
    ///
    /// # Errors
    /// [`PatchError`] if the path or a sibling needed for branch collapse is unproved or malformed.
    /// The error remains sticky until [`Self::reset`].
    pub fn remove(&mut self, key: &[u8; 32]) -> Result<bool, PatchError> {
        self.update(key, None)
    }

    /// Computes the root, hashing changed nodes once and reusing untouched commitments.
    ///
    /// # Errors
    /// The first update error, if any. Finalization never resolves additional witness nodes.
    ///
    /// # Panics
    /// Panics if the internal encoder violates list arity or child-before-parent ordering.
    pub fn root_hash(&mut self) -> Result<[u8; 32], PatchError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(match self.commit(self.root) {
            Reference::Empty => EMPTY_ROOT_HASH,
            Reference::Hash(hash) => hash,
            Reference::Inline { bytes, len } => {
                #[cfg(test)]
                {
                    self.hashes += 1;
                }
                keccak256(&bytes[..usize::from(len)])
            }
        })
    }

    fn update(&mut self, key: &[u8; 32], value: Option<&[u8]>) -> Result<bool, PatchError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        match self.update_at(self.root, Prefix::key(*key), value, [0; 32], false) {
            Ok((root, changed)) => {
                self.root = root;
                Ok(changed)
            }
            Err(error) => {
                let error = PatchError::Node(error);
                self.failure = Some(error);
                Err(error)
            }
        }
    }

    fn push(&mut self, kind: Kind<'store>, origin: [u8; 32]) -> Link<'store> {
        let index = self.nodes.len();
        self.nodes.push(Owned {
            kind,
            origin,
            cached: None,
        });
        Link::Owned(index)
    }

    fn value(&self, value: Value<'store>) -> &[u8] {
        match value {
            Value::Borrowed(bytes) => bytes,
            Value::Arena { start, len } => &self.values[start..start + len],
        }
    }

    fn save_value(&mut self, bytes: &[u8]) -> Value<'store> {
        let start = self.values.len();
        self.values.extend_from_slice(bytes);
        Value::Arena {
            start,
            len: bytes.len(),
        }
    }

    /// Borrows one witness node, enforcing secure-key depth and extension-target invariants.
    fn witness_node(
        &self,
        link: Link<'store>,
        remaining: u8,
        origin: [u8; 32],
        require_branch: bool,
    ) -> Result<(Node<'store>, [u8; 32], Reference), LookupError> {
        let (bytes, decoded, origin, cached) = match link {
            Link::Hash(hash) => {
                let (bytes, decoded) = self.store.node(&hash, remaining == 64)?;
                (bytes, decoded, hash, Reference::Hash(hash))
            }
            Link::Embedded(bytes) => (
                bytes,
                Decoded::decode(bytes).map_err(|_| LookupError::MalformedNode(origin))?,
                origin,
                Reference::inline(bytes),
            ),
            // Empty links are handled by the update/collapse callers before resolution.
            Link::Empty | Link::Owned(_) => return Err(LookupError::MalformedNode(origin)),
        };
        let malformed = LookupError::MalformedNode(origin);
        let node = decoded.view(bytes);
        if require_branch && !matches!(node, Node::Branch(_)) {
            return Err(malformed);
        }
        match &node {
            Node::Leaf { path, value } => {
                if path.len() != usize::from(remaining) || value.is_empty() {
                    return Err(malformed);
                }
            }
            Node::Extension { path, .. } => {
                if path.len() >= usize::from(remaining) {
                    return Err(malformed);
                }
            }
            Node::Branch(branch) => {
                if remaining == 0 || branch.value().is_some() {
                    return Err(malformed);
                }
            }
        }
        Ok((node, origin, cached))
    }

    /// Materializes a node only when an update or branch collapse needs an owned representation.
    fn resolve(
        &mut self,
        link: Link<'store>,
        remaining: u8,
        origin: [u8; 32],
        require_branch: bool,
    ) -> Result<usize, LookupError> {
        if let Link::Owned(index) = link {
            if require_branch && !matches!(self.nodes[index].kind, Kind::Branch(_)) {
                return Err(LookupError::MalformedNode(self.nodes[index].origin));
            }
            return Ok(index);
        }
        let (node, origin, cached) = self.witness_node(link, remaining, origin, require_branch)?;
        let kind = match node {
            Node::Leaf { path, value } => Kind::Leaf {
                path: Prefix::from_path(path),
                value: Value::Borrowed(value),
            },
            Node::Extension { path, child } => Kind::Extension {
                path: Prefix::from_path(path),
                child: child_link(child),
            },
            Node::Branch(branch) => {
                let index = self.branches.len();
                self.branches.push(core::array::from_fn(|i| {
                    branch
                        .child(i.to_le_bytes()[0])
                        .map_or(Link::Empty, child_link)
                }));
                Kind::Branch(index)
            }
        };
        let index = self.nodes.len();
        self.nodes.push(Owned {
            kind,
            origin,
            cached: Some(cached),
        });
        Ok(index)
    }

    fn update_at(
        &mut self,
        link: Link<'store>,
        key: Prefix,
        value: Option<&[u8]>,
        origin: [u8; 32],
        require_branch: bool,
    ) -> Result<(Link<'store>, bool), LookupError> {
        if matches!(link, Link::Empty | Link::Owned(_)) {
            return self.update_node(link, key, value, origin, require_branch);
        }
        // Walk borrowed nodes first: unchanged reads need neither arena space nor copied branches.
        let (node, origin, _) = self.witness_node(link, key.len, origin, require_branch)?;
        match node {
            Node::Leaf { path, value: old } => {
                let path = Prefix::from_path(path);
                let matches = path.common(key) == path.len;
                if (matches && value == Some(old)) || (!matches && value.is_none()) {
                    return Ok((link, false));
                }
                if matches && value.is_none() {
                    return Ok((Link::Empty, true));
                }
                let owned = self.push(
                    Kind::Leaf {
                        path,
                        value: Value::Borrowed(old),
                    },
                    origin,
                );
                self.update_node(owned, key, value, origin, false)
            }
            Node::Extension { path, child } => {
                let path = Prefix::from_path(path);
                if path.common(key) != path.len {
                    if value.is_none() {
                        return Ok((link, false));
                    }
                    let owned = self.push(
                        Kind::Extension {
                            path,
                            child: child_link(child),
                        },
                        origin,
                    );
                    return self.update_node(owned, key, value, origin, false);
                }
                let (child, changed) =
                    self.update_at(child_link(child), key.suffix(path.len), value, origin, true)?;
                if !changed {
                    return Ok((link, false));
                }
                let link = if value.is_none() {
                    self.collapse_extension(path, child, origin)
                } else {
                    self.extend(path, child, origin)
                };
                Ok((link, true))
            }
            Node::Branch(branch) => {
                let nibble = key.nibble(0);
                let child = branch.child(nibble).map_or(Link::Empty, child_link);
                let (child, changed) =
                    self.update_at(child, key.suffix(1), value, origin, false)?;
                if !changed {
                    return Ok((link, false));
                }
                let branch_index = self.branches.len();
                self.branches.push(core::array::from_fn(|i| {
                    if i == usize::from(nibble) {
                        child
                    } else {
                        branch
                            .child(i.to_le_bytes()[0])
                            .map_or(Link::Empty, child_link)
                    }
                }));
                let index = self.nodes.len();
                let link = self.push(Kind::Branch(branch_index), origin);
                if value.is_none() {
                    return self
                        .collapse_branch(index, branch_index, key.len, origin)
                        .map(|link| (link, true));
                }
                Ok((link, true))
            }
        }
    }

    fn update_node(
        &mut self,
        link: Link<'store>,
        key: Prefix,
        value: Option<&[u8]>,
        origin: [u8; 32],
        require_branch: bool,
    ) -> Result<(Link<'store>, bool), LookupError> {
        if matches!(link, Link::Empty) {
            return Ok(value.map_or((Link::Empty, false), |bytes| {
                let value = self.save_value(bytes);
                (self.push(Kind::Leaf { path: key, value }, origin), true)
            }));
        }
        let index = self.resolve(link, key.len, origin, require_branch)?;
        let Owned { kind, origin, .. } = self.nodes[index];
        let changed = match kind {
            Kind::Leaf { path, value: old } => {
                let common = path.common(key);
                if common == path.len {
                    let Some(bytes) = value else {
                        return Ok((Link::Empty, true));
                    };
                    if self.value(old) == bytes {
                        return Ok((Link::Owned(index), false));
                    }
                    let value = self.save_value(bytes);
                    self.nodes[index].kind = Kind::Leaf { path, value };
                } else {
                    let Some(bytes) = value else {
                        return Ok((Link::Owned(index), false));
                    };
                    let old = self.push(
                        Kind::Leaf {
                            path: path.suffix(common + 1),
                            value: old,
                        },
                        origin,
                    );
                    return Ok((self.split(path, key, common, old, bytes, origin), true));
                }
                true
            }
            Kind::Extension { path, child } => {
                let common = path.common(key);
                if common != path.len {
                    let Some(bytes) = value else {
                        return Ok((Link::Owned(index), false));
                    };
                    let rest = path.suffix(common + 1);
                    let old = self.extend(rest, child, origin);
                    return Ok((self.split(path, key, common, old, bytes, origin), true));
                }
                let (child, changed) =
                    self.update_at(child, key.suffix(path.len), value, origin, true)?;
                self.nodes[index].kind = Kind::Extension { path, child };
                if changed && value.is_none() {
                    return Ok((self.collapse_extension(path, child, origin), true));
                }
                changed
            }
            Kind::Branch(branch) => {
                let nibble = usize::from(key.nibble(0));
                let (child, changed) = self.update_at(
                    self.branches[branch][nibble],
                    key.suffix(1),
                    value,
                    origin,
                    false,
                )?;
                self.branches[branch][nibble] = child;
                if changed && value.is_none() {
                    self.nodes[index].cached = None;
                    return self
                        .collapse_branch(index, branch, key.len, origin)
                        .map(|link| (link, true));
                }
                changed
            }
        };
        if changed {
            self.nodes[index].cached = None;
        }
        Ok((Link::Owned(index), changed))
    }

    /// Splits diverging short nodes into a branch, optionally under their common extension.
    fn split(
        &mut self,
        path: Prefix,
        key: Prefix,
        common: u8,
        old: Link<'store>,
        bytes: &[u8],
        origin: [u8; 32],
    ) -> Link<'store> {
        let mut children = [Link::Empty; 16];
        children[usize::from(path.nibble(common))] = old;
        let value = self.save_value(bytes);
        children[usize::from(key.nibble(common))] = self.push(
            Kind::Leaf {
                path: key.suffix(common + 1),
                value,
            },
            origin,
        );
        let branch = self.branches.len();
        self.branches.push(children);
        let child = self.push(Kind::Branch(branch), origin);
        self.extend(path.take(common), child, origin)
    }

    fn extend(&mut self, path: Prefix, child: Link<'store>, origin: [u8; 32]) -> Link<'store> {
        if path.len == 0 {
            child
        } else {
            self.push(Kind::Extension { path, child }, origin)
        }
    }

    fn collapse_extension(
        &mut self,
        path: Prefix,
        child: Link<'store>,
        origin: [u8; 32],
    ) -> Link<'store> {
        match child {
            Link::Empty => Link::Empty,
            Link::Owned(index) => match self.nodes[index].kind {
                Kind::Leaf {
                    path: suffix,
                    value,
                } => self.push(
                    Kind::Leaf {
                        path: path.join(suffix),
                        value,
                    },
                    origin,
                ),
                Kind::Extension {
                    path: suffix,
                    child,
                } => self.extend(path.join(suffix), child, origin),
                Kind::Branch(_) => self.extend(path, child, origin),
            },
            _ => self.extend(path, child, origin),
        }
    }

    fn collapse_branch(
        &mut self,
        index: usize,
        branch: usize,
        remaining: u8,
        origin: [u8; 32],
    ) -> Result<Link<'store>, LookupError> {
        let mut live = self.branches[branch]
            .iter()
            .enumerate()
            .filter(|(_, child)| !matches!(child, Link::Empty));
        let Some((nibble, &child)) = live.next() else {
            return Ok(Link::Empty);
        };
        if live.next().is_some() {
            return Ok(Link::Owned(index));
        }
        // Collapsing a unary branch needs the surviving node's path, not merely its hash.
        let child = self.resolve(child, remaining - 1, origin, false)?;
        let mut prefix = Prefix::key([0; 32]).take(1);
        prefix.set(0, nibble.to_le_bytes()[0]);
        Ok(self.collapse_extension(prefix, Link::Owned(child), origin))
    }

    /// Resolves only cached references here; all fallible witness access happens during updates.
    fn reference(&self, link: Link<'store>) -> Option<Reference> {
        match link {
            Link::Empty => Some(Reference::Empty),
            Link::Hash(hash) => Some(Reference::Hash(hash)),
            Link::Embedded(bytes) => Some(Reference::inline(bytes)),
            Link::Owned(index) => self.nodes[index].cached,
        }
    }

    /// Encodes dirty nodes after their children and caches each canonical reference.
    ///
    /// # Panics
    /// Panics on an internal list-arity or child-cache invariant violation.
    fn commit(&mut self, link: Link<'store>) -> Reference {
        if let Some(reference) = self.reference(link) {
            return reference;
        }
        let Link::Owned(index) = link else {
            unreachable!("only owned nodes have uncached references")
        };
        let kind = self.nodes[index].kind;
        match kind {
            Kind::Leaf { .. } => {}
            Kind::Extension { child, .. } => {
                self.commit(child);
            }
            Kind::Branch(branch) => {
                for i in 0..16 {
                    self.commit(self.branches[branch][i]);
                }
            }
        }
        self.scratch.clear();
        match kind {
            Kind::Leaf { path, value } => {
                self.append_path(path, true);
                let bytes = match value {
                    Value::Borrowed(bytes) => bytes,
                    Value::Arena { start, len } => &self.values[start..start + len],
                };
                self.scratch.append(&bytes);
            }
            Kind::Extension { path, child } => {
                self.append_path(path, false);
                self.append_committed(child);
            }
            Kind::Branch(branch) => {
                self.scratch.begin_list(17);
                for i in 0..16 {
                    self.append_committed(self.branches[branch][i]);
                }
                self.scratch.append_empty_data();
            }
        }
        // A partial list would silently change a consensus commitment when read via as_raw().
        assert!(self.scratch.is_finished(), "incomplete trie node encoding");
        let raw = self.scratch.as_raw();
        let reference = if raw.len() < 32 {
            Reference::inline(raw)
        } else {
            #[cfg(test)]
            {
                self.hashes += 1;
            }
            Reference::Hash(keccak256(raw))
        };
        self.nodes[index].cached = Some(reference);
        reference
    }

    fn append_path(&mut self, path: Prefix, leaf: bool) {
        let mut encoded = [0; 33];
        let len = path.encode(leaf, &mut encoded);
        self.scratch.begin_list(2);
        self.scratch.append(&&encoded[..len]);
    }

    fn append_committed(&mut self, child: Link<'store>) {
        // commit() visits children first; a missing cache is an encoder bug, never witness input.
        self.reference(child)
            .expect("child committed before parent")
            .append(&mut self.scratch);
    }
}

const fn root_link(root: [u8; 32]) -> Link<'static> {
    if matches!(root, EMPTY_ROOT_HASH) {
        Link::Empty
    } else {
        Link::Hash(root)
    }
}

const fn child_link(child: Child<'_>) -> Link<'_> {
    match child {
        Child::Hash(hash) => Link::Hash(hash),
        Child::Embedded(bytes) => Link::Embedded(bytes),
    }
}
