//! Ordered MPT construction specialized for the keys `RLP(0..len)`.
//!
//! Index ranges determine branch and extension paths without sorting or storing keys.
//! Completed nodes collapse to inline RLP (<32 bytes) or hash references. Large leaf values
//! go directly to Keccak, so scratch capacity depends on key depth, not payload size.
//!
//! This specializes the recursive node construction in the [Yellow Paper], Appendix D, for dense
//! RLP indices. [Alloy 0.9.5] provides a reference for the same lexicographic index order.
//! Range splitting and scratch tiers are specific to this implementation; see the
//! [algorithm derivation and memory bound](crate#algorithm).
//!
//! [Yellow Paper]: https://ethereum.github.io/yellowpaper/paper.pdf
//! [Alloy 0.9.5]: https://docs.rs/alloy-trie/0.9.5/src/alloy_trie/root.rs.html

use crate::crypto::TrieHasher;

#[cfg(test)]
mod tests;

/// Stack scratch bytes for up to 128 items, whose RLP keys each occupy one byte.
const SHORT_KEY_STACK_CAPACITY: usize = 960;
/// Stack scratch bytes for up to 256 items, whose indices fit in a `u8`.
const U8_INDEX_STACK_CAPACITY: usize = 1792;
/// Stack scratch bytes for up to 65,536 items, whose indices fit in a `u16`.
const U16_INDEX_STACK_CAPACITY: usize = 2880;

/// Supplies each value once, in lexicographic RLP-key order (not transaction order).
trait Values {
    /// Returns the number of consecutively indexed values.
    fn len(&self) -> usize;
    /// Borrows the value at `index` until the next mutable access to this source.
    fn value(&mut self, index: usize) -> &[u8];
}

/// Borrows already encoded values directly from an indexed slice.
struct SliceValues<'a, T>(&'a [T]);

impl<T: AsRef<[u8]>> Values for SliceValues<'_, T> {
    /// Returns the number of values in the borrowed slice.
    fn len(&self) -> usize {
        self.0.len()
    }
    /// Borrows an encoded value without allocating or copying its bytes.
    fn value(&mut self, index: usize) -> &[u8] {
        self.0[index].as_ref()
    }
}

/// Computes a root without materializing keys, node objects, or copies of the input values.
pub fn root_of<T: AsRef<[u8]>>(items: &[T]) -> [u8; 32] {
    build(&mut SliceValues(items))
}

/// Encodes indexed items on demand into one reusable RLP stream.
struct EncodedValues<'a, T, F> {
    items: &'a [T],
    encode: F,
    scratch: rlp::RlpStream,
}

impl<T, F> Values for EncodedValues<'_, T, F>
where
    F: for<'s> FnMut(&T, &'s mut rlp::RlpStream) -> &'s [u8],
{
    /// Returns the number of items available to the encoder.
    fn len(&self) -> usize {
        self.items.len()
    }
    /// Encodes one item and borrows the result from the shared scratch stream.
    fn value(&mut self, index: usize) -> &[u8] {
        (self.encode)(&self.items[index], &mut self.scratch)
    }
}

/// Encodes each item once into one reusable stream, consuming its slice before the next item.
pub fn root_with_encoder<T, F>(items: &[T], encode: F) -> [u8; 32]
where
    F: for<'s> FnMut(&T, &'s mut rlp::RlpStream) -> &'s [u8],
{
    // An empty trie needs neither an encoder buffer nor a node buffer.
    if items.is_empty() {
        return crate::EMPTY_ROOT_HASH;
    }
    build(&mut EncodedValues {
        items,
        encode,
        scratch: rlp::RlpStream::new(),
    })
}

/// Selects the empty root, single-leaf fast path, or bounded-scratch branch builder.
fn build(items: &mut impl Values) -> [u8; 32] {
    match items.len() {
        0 => crate::EMPTY_ROOT_HASH,
        1 => hash_leaf(0x80, 2, items.value(0)),
        count => build_branch(items, capacity_for(count)),
    }
}

/// Keeps the single-leaf path out of the large scratch stack frame.
#[inline(never)]
fn build_branch(items: &mut impl Values, capacity: usize) -> [u8; 32] {
    if capacity <= SHORT_KEY_STACK_CAPACITY {
        root(&mut [0; SHORT_KEY_STACK_CAPACITY], items)
    } else if capacity <= U8_INDEX_STACK_CAPACITY {
        root(&mut [0; U8_INDEX_STACK_CAPACITY], items)
    } else if capacity <= U16_INDEX_STACK_CAPACITY {
        root(&mut [0; U16_INDEX_STACK_CAPACITY], items)
    } else {
        root(&mut vec![0; capacity], items)
    }
}

/// Bounds live payloads along a root-to-leaf path; requires `count >= 2`.
///
/// Root and index-width branches use at most nine 33-byte references plus eight empty items.
/// Each remaining nibble adds at most a full branch (529 bytes) and an extension path (10).
/// The final 64 bytes cover a pending leaf/reference and list-prefix insertion.
fn capacity_for(count: usize) -> usize {
    const NARROW: usize = 9 * 33 + 8;
    const WIDE: usize = 16 * 33 + 1 + 10;

    let last = count - 1;
    let depth = if last < 0x80 { 0 } else { 2 * byte_width(last) };
    NARROW
        + if depth == 0 {
            WIDE
        } else {
            NARROW + depth * WIDE
        }
        + 64
}

/// Scratch for open node payloads. All writes remain bounds-checked.
struct NodeBuffer<'a> {
    data: &'a mut [u8],
    len: usize,
    hasher: TrieHasher,
}

impl NodeBuffer<'_> {
    /// Appends one byte to the payloads of the currently open nodes.
    #[inline]
    fn push(&mut self, byte: u8) {
        self.data[self.len] = byte;
        self.len += 1;
    }

    /// Copies a byte slice into the payloads of the currently open nodes.
    #[inline]
    fn extend(&mut self, bytes: &[u8]) {
        self.data[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    /// Replaces the finished node with its RLP-encoded hash reference.
    fn seal(&mut self, start: usize) {
        let digest = self.hasher.finalize_reset();
        self.len = start;
        self.push(0xa0);
        self.extend(&digest);
    }
}

/// Emits the root branch and hashes it. `items.len() >= 2`.
fn root(data: &mut [u8], items: &mut impl Values) -> [u8; 32] {
    let count = items.len();
    let buffer = &mut NodeBuffer {
        data,
        len: 0,
        hasher: TrieHasher::new(),
    };

    // Slots 0..=7: single-byte keys `0x01..=0x7f`, i.e. indices `1..=min(count-1, 127)`.
    let last_short = (count - 1).min(0x7f);
    for slot in 0..8usize {
        let first = if slot == 0 { 1 } else { slot << 4 };
        let top = (slot << 4) + 15;
        let last = top.min(last_short);
        if first > last {
            buffer.push(0x80);
        } else {
            append_subtree(buffer, 1, first, last, items);
        }
    }

    // Slot 8: index 0 alone, or a branch over index 0 and the multi-byte groups.
    if count <= 0x80 {
        // Only `0x80` lives here; one nibble of path is left after the branch consumed the `8`.
        append_leaf(buffer, 0, 1, items.value(0));
    } else {
        index_width_branch(buffer, items);
    }

    for _ in 9..16 {
        buffer.push(0x80);
    }
    buffer.push(0x80); // Branch value slot: no key is a prefix of another, so always empty.

    // The root node is hashed whatever its size, so no inline check here.
    let mut header = [0u8; 9];
    let prefix_len = put_list_header(&mut header, buffer.len);
    buffer.hasher.update(&header[..prefix_len]);
    buffer.hasher.update(&buffer.data[..buffer.len]);
    buffer.hasher.finalize_reset()
}

/// The branch under root nibble 8: slot 0 is index 0, slot `width` is the `width`-byte-wide index group.
fn index_width_branch(buffer: &mut NodeBuffer<'_>, items: &mut impl Values) {
    let start = buffer.len;
    let last = items.len() - 1;
    append_leaf(buffer, 0, 0, items.value(0)); // key `0x80`: nibbles (8, 0), both consumed by the two branches
    let widest = size_of::<usize>();
    for width in 1..16_usize {
        let first = if width == 1 {
            0x80
        } else if width <= widest {
            1usize << (8 * (width - 1))
        } else {
            usize::MAX // unreachable slot; forces the empty marker below
        };
        if width > widest || first > last {
            buffer.push(0x80);
            continue;
        }
        let top = if width == widest {
            usize::MAX
        } else {
            (1usize << (8 * width)) - 1
        };
        let last = last.min(top);
        append_subtree(buffer, 2 * width, first, last, items);
    }
    buffer.push(0x80); // value slot
    finish_node(buffer, start);
}

/// Emits the node covering the low `remaining` nibbles of every index in `first..=last`, then collapses it to a
/// parent-facing child reference. `first` and `last` agree above those `remaining` nibbles.
fn append_subtree(
    buffer: &mut NodeBuffer<'_>,
    remaining: usize,
    first: usize,
    last: usize,
    items: &mut impl Values,
) {
    if first == last {
        append_leaf(buffer, first, remaining, items.value(first));
        return;
    }
    // A contiguous range shares exactly the leading nibbles that its endpoints share.
    let differing = nibble_width(first ^ last);
    let shared = remaining - differing;
    let start = buffer.len;
    if shared == 0 {
        append_branch(buffer, remaining, first, last, items);
    } else {
        append_extension_path(buffer, first, remaining, shared);
        let child = buffer.len;
        append_branch(buffer, differing, first, last, items);
        finish_node(buffer, child);
    }
    finish_node(buffer, start);
}

/// Emits the 17 payload items of a branch splitting on the top of the `remaining`-nibble window.
fn append_branch(
    buffer: &mut NodeBuffer<'_>,
    remaining: usize,
    first: usize,
    last: usize,
    items: &mut impl Values,
) {
    let unit = 1usize << (4 * (remaining - 1));
    let base = if remaining >= size_of::<usize>() * 2 {
        0
    } else {
        (first >> (4 * remaining)) << (4 * remaining)
    };
    for slot in 0..16usize {
        let slot_first = base + slot * unit;
        let slot_last = slot_first + (unit - 1);
        let child_first = slot_first.max(first);
        let child_last = slot_last.min(last);
        if child_first > child_last {
            buffer.push(0x80);
        } else if remaining == 1 {
            append_leaf(buffer, child_first, 0, items.value(child_first)); // path exhausted: leaf with an empty remainder
        } else {
            append_subtree(buffer, remaining - 1, child_first, child_last, items);
        }
    }
    buffer.push(0x80); // value slot
}

/// Replaces the node RLP payload written at `start` with the reference its parent stores.
fn finish_node(buffer: &mut NodeBuffer<'_>, start: usize) {
    let payload = buffer.len - start;
    // `payload < 32` implies `payload < 56`, so the header is one byte in the inline case.
    if payload + 1 < 32 {
        buffer.data.copy_within(start..buffer.len, start + 1);
        buffer.data[start] = 0xc0 + payload.to_le_bytes()[0];
        buffer.len += 1;
        return;
    }
    let mut header = [0u8; 9];
    let prefix_len = put_list_header(&mut header, payload);
    buffer.hasher.update(&header[..prefix_len]);
    buffer.hasher.update(&buffer.data[start..buffer.len]);
    buffer.seal(start);
}

/// Emits a leaf reference, hashing large values directly without copying them into scratch.
fn append_leaf(buffer: &mut NodeBuffer<'_>, path: usize, remaining: usize, value: &[u8]) {
    let mut head = [0u8; 32];
    let (prefix_len, remaining_value_len) = leaf_prefix(&mut head, path, remaining, value);
    if prefix_len + remaining_value_len < 32 {
        buffer.extend(&head[..prefix_len]);
        if remaining_value_len > 0 {
            buffer.extend(value);
        }
    } else {
        buffer.hasher.update(&head[..prefix_len]);
        if remaining_value_len > 0 {
            buffer.hasher.update(value);
        }
        buffer.seal(buffer.len);
    }
}

/// The `count == 1` case: a lone leaf that is the root node, hence always hashed.
fn hash_leaf(path: usize, remaining: usize, value: &[u8]) -> [u8; 32] {
    let mut head = [0u8; 32];
    let (prefix_len, remaining_value_len) = leaf_prefix(&mut head, path, remaining, value);
    let mut hasher = TrieHasher::new();
    hasher.update(&head[..prefix_len]);
    if remaining_value_len > 0 {
        hasher.update(value);
    }
    hasher.finalize_reset()
}

/// Writes `rlp_list_header ++ rlp(hex_prefix) ++ rlp_header(value)` into `head`.
/// Returns the bytes written and how many value bytes still have to follow.
fn leaf_prefix(head: &mut [u8; 32], path: usize, remaining: usize, value: &[u8]) -> (usize, usize) {
    let mut path_bytes = [0u8; 9];
    let path_len = hex_prefix(&mut path_bytes, path, remaining, remaining, true);
    // `hex_prefix` always yields a first byte of 0x20..=0x3f, so a one-byte prefix is its own RLP.
    let path_rlp_len = if path_len == 1 { 1 } else { 1 + path_len };
    let value_len = value.len();
    let single = value_len == 1 && value[0] < 0x80;
    let value_rlp_len = if single {
        1
    } else if value_len < 56 {
        1 + value_len
    } else {
        1 + byte_width(value_len) + value_len
    };

    let mut i = put_list_header(head, path_rlp_len + value_rlp_len);
    if path_len == 1 {
        head[i] = path_bytes[0];
        i += 1;
    } else {
        head[i] = 0x80 + path_len.to_le_bytes()[0];
        i += 1;
        head[i..i + path_len].copy_from_slice(&path_bytes[..path_len]);
        i += path_len;
    }
    if single {
        head[i] = value[0];
        i += 1;
        return (i, 0);
    }
    if value_len < 56 {
        head[i] = 0x80 + value_len.to_le_bytes()[0];
        i += 1;
    } else {
        let k = byte_width(value_len);
        head[i] = 0xb7 + k.to_le_bytes()[0];
        i += 1;
        put_be(&mut head[i..], value_len, k);
        i += k;
    }
    (i, value_len)
}

/// Writes the hex-prefix of the top `take` nibbles of the `remaining`-nibble window of `path` as an RLP
/// string. Only extension nodes go through here, so the first byte is 0x00..=0x1f — never escaped.
fn append_extension_path(buffer: &mut NodeBuffer<'_>, path: usize, remaining: usize, take: usize) {
    let mut path_bytes = [0u8; 9];
    let path_len = hex_prefix(&mut path_bytes, path, remaining, take, false);
    if path_len == 1 {
        buffer.push(path_bytes[0]);
    } else {
        buffer.push(0x80 + path_len.to_le_bytes()[0]);
        buffer.extend(&path_bytes[..path_len]);
    }
}

/// Hex-prefix encoding of the top `take` nibbles of the low `remaining` nibbles of `path`.
const fn hex_prefix(
    out: &mut [u8; 9],
    path: usize,
    remaining: usize,
    take: usize,
    leaf: bool,
) -> usize {
    let flag = if leaf { 2u8 } else { 0u8 };
    let stop = remaining - take;
    let mut p = remaining;
    if take & 1 == 1 {
        p -= 1;
        out[0] = ((flag + 1) << 4) | (path >> (4 * p)).to_le_bytes()[0] & 15;
    } else {
        out[0] = flag << 4;
    }

    let mut i = 1;
    while p > stop {
        let last = (path >> (4 * (p - 1))) & 15;
        let first = (path >> (4 * (p - 2))) & 15;
        out[i] = ((last << 4) | first).to_le_bytes()[0];
        i += 1;
        p -= 2;
    }
    i
}

/// Writes an RLP list header for `payload` bytes and returns the header length.
fn put_list_header(out: &mut [u8], payload: usize) -> usize {
    if payload < 56 {
        out[0] = 0xc0 + payload.to_le_bytes()[0];
        return 1;
    }
    let k = byte_width(payload);
    out[0] = 0xf7 + k.to_le_bytes()[0];
    put_be(&mut out[1..], payload, k);
    1 + k
}

/// Writes the low `k` bytes of `v` in big-endian order.
fn put_be(out: &mut [u8], v: usize, k: usize) {
    for (j, slot) in out[..k].iter_mut().enumerate() {
        *slot = (v >> (8 * (k - 1 - j))).to_le_bytes()[0];
    }
}

/// Bytes needed for the minimal big-endian encoding of `v` (at least one).
fn byte_width(v: usize) -> usize {
    let bits = usize::BITS - v.leading_zeros();
    if bits == 0 {
        1
    } else {
        // This count is at most size_of::<usize>(), so conversion cannot fail.
        usize::try_from(bits.div_ceil(8)).expect("byte width fits usize")
    }
}

/// Nibbles needed for the minimal big-endian encoding of `v` (zero for `v == 0`).
fn nibble_width(v: usize) -> usize {
    // At most two nibbles per native byte; representable on both RV32 and 64-bit hosts.
    usize::try_from((usize::BITS - v.leading_zeros()).div_ceil(4)).expect("nibble width fits usize")
}
