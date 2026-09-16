# Algorithm

## Sources and scope

The protocol rules come from the [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf):
Appendix B defines RLP, Appendix C defines hex-prefix encoding, and Appendix D
defines recursive Merkle-Patricia construction and child references. This builder
specializes those rules for dense keys `RLP(index)`, where `index` is in `0..len`.

[Alloy 0.9.5's ordered-root implementation](https://docs.rs/alloy-trie/0.9.5/src/alloy_trie/root.rs.html)
is a related reference: `adjust_index_for_rlp` gives the same key order, and
`ordered_trie_root_with_encoder` reuses an encoding buffer. The range decomposition
and scratch bounds below describe this implementation; they are not algorithms
or memory guarantees specified by those sources.

## Traversal and node construction

1. Empty input returns the canonical empty root. One item produces a single leaf
   for key `RLP(0) = 0x80`, without allocating node scratch.
2. For two or more items, the root is a branch. Indices `1..=127` encode as their
   own byte; index zero encodes as `0x80`; larger indices encode as a byte-width
   prefix followed by the big-endian integer. Consequently, lexicographic key
   order is `1..=min(len - 1, 127)`, then `0`, then `128..len`.
3. Root slots `0..=7` cover the short nonzero indices. Slot `8` contains index
   zero and, when present, a second branch separating indices by byte width.
   Within each width group, numeric order is also lexicographic order.
4. `append_subtree` processes a contiguous index interval. A singleton becomes a
   leaf. Otherwise, `first ^ last` identifies the differing suffix: the leading
   nibbles shared by both endpoints are shared by the entire interval. A shared
   prefix becomes an extension; the next differing nibble selects branch slots.
   Intersecting each slot's numeric interval with the input interval gives its
   child, without constructing or sorting serialized keys.
5. Nodes are completed bottom-up in `NodeBuffer`. An encoded child shorter than
   32 bytes remains inline; any larger child is replaced with an RLP-encoded
   Keccak-256 digest. The root is always hashed. Large leaf values go directly
   into the hash state instead of being copied into node scratch.

Each split partitions its interval into disjoint children, so each value is
consumed exactly once. Every step consumes the corresponding key nibbles, and
hex-prefix encoding distinguishes leaf endings from extensions. No complete RLP
index key prefixes another, so branch value slots are empty. These invariants
connect the interval traversal to the recursive MPT construction.

The encoder variant visits items in the same order and consumes each borrowed
encoding before the next encoder call. Its reusable `RlpStream` is separate from
node scratch.

## Scratch bound and stack tiers

`capacity_for` bounds unfinished payloads along the active root-to-leaf path.
A child reference occupies at most 33 bytes. On supported 32- and 64-bit targets,
the root and byte-width branches have at most nine nonempty child slots:

- Narrow branch: `9 * 33 + 8 = 305` bytes.
- Full branch plus extension allowance: `16 * 33 + 1 + 10 = 539` bytes.
- Pending leaf/reference and list-prefix insertion allowance: 64 bytes.

For short keys the bound is `305 + 539 + 64 = 908` bytes. Otherwise, let
`d = 2 * byte_width(len - 1)` be the integer's nibble width; the bound is
`305 + 305 + d * 539 + 64`. The implementation rounds common bounds up to
multiples of 64 for its fixed array sizes; this does not imply 64-byte alignment.

| Item count | Calculated bound | Selected scratch |
| --- | ---: | --- |
| 0 or 1 | No node buffer | None |
| 2 through 128 | 908 bytes | `SHORT_KEY_STACK_CAPACITY`: 960 bytes |
| 129 through 256 | 1,752 bytes | `U8_INDEX_STACK_CAPACITY`: 1,792 bytes |
| 257 through 65,536 | 2,830 bytes | `U16_INDEX_STACK_CAPACITY`: 2,880 bytes |
| 65,537, for example | 3,908 bytes | One heap buffer of the calculated size |

These sizes cover node scratch, not the entire stack frame, recursion, or hash
state. Scratch growth depends on native index width, not total value bytes.
The encoder's additional memory depends on its largest encoded item and list
nesting. `build_branch` stays out of line so the single-leaf path avoids its
large scratch stack frame.
