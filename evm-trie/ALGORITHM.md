# Algorithm

## Sources and scope

The protocol rules come from the [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf):
Appendix B defines RLP, Appendix C defines hex-prefix encoding, and Appendix D
defines recursive Merkle-Patricia construction and child references. The ordered
builder specializes those rules for dense keys `RLP(index)`, where `index` is in
`0..len`. The read-only sparse lookup below follows the same node format for
arbitrary byte paths, including prehashed state and storage keys.

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

## Sparse witness lookups

`sparse::NodeStore` reads a partially revealed MPT; it does not construct or update
state roots. Node encoding follows Yellow Paper Appendices B–D. The proof model
is also described in [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186): RLP nodes
are authenticated against a separately trusted root. This module consumes nodes,
not the RPC response format or decoded account/storage values.

### Traversal and proof outcomes

1. Construction hashes each supplied RLP blob, validates its encoding, and stores
   compact field offsets beside the original bytes in a sorted vector. Duplicate
   hashes retain one entry. Decoding errors are stored and reported only if lookup
   reaches that node; unused malformed blobs do not invalidate a proof.
2. Lookup takes a trusted root and a byte path. Secure-trie callers hash the
   address or storage key first; `get` does not hash keys. The canonical empty
   root proves absence without requiring a node.
3. A branch consumes one nibble and selects a child, or returns its value when
   the key ends. An empty child or value proves absence.
4. An extension consumes its matching hex-prefix path; a mismatch proves absence.
   A leaf returns its borrowed value only if the entire remaining path matches.
5. Hash references resolve through the store; embedded children borrow their RLP
   directly from the parent. Canonical MPT children are embedded only when their
   entire RLP is shorter than 32 bytes; roots are always addressed by hash.
6. A required but unrevealed hash returns `BlindedNode`, not absence. Detected
   decoding failures return `MalformedNode`; for embedded data, the error names
   the containing hashed node.

The root must be trusted separately. Hashing supplied bytes prevents substitution
under that root, assuming Keccak-256 collision resistance; witness lookup does
not establish consensus validity of the root itself.

The decoder checks exact RLP boundaries, minimal length encodings, node arity,
hex-prefix flags and padding, child reference sizes, nonempty extension paths,
and branches with at least two occupied entries. All embedded descendants are
validated; their sub-32-byte encodings bound recursion depth. An extension must
lead to a branch, and a hashed non-root child must encode to at least 32 bytes.
For hashed children these two checks run when the child is followed: an
unrevealed subtree remains valid partial-witness input, and is not required to
prove exclusion along a different path. This validates visited structure, not
unrevealed parts of the entire trie.

### Cost and test reference

For `N` supplied nodes containing `B` bytes, construction hashes and parses the
bytes and sorts the index in `O(B + N log N)` time, retaining `O(B + N)` memory.
It moves the supplied RLP buffers without copying them. An exact-size input such
as `Vec<Vec<u8>>` needs one retained index allocation (zero for an empty input).
Already sorted hashes, including empty and singleton inputs, skip sorting scratch.
Otherwise, one temporary vector holds `(big-endian u64 prefix, usize source)` keys:
16 bytes per input node on RV32 and 64-bit targets. Equal prefixes are
ordered by the full hash, so collisions cannot change results or trigger linear
probing. Sorting costs `O(N log N)` even when all prefixes collide.

The sorted source indices form a permutation. Each disjoint cycle is applied
in place with at most one swap per entry; completed positions are marked with
`usize::MAX` in the key vector itself. Slice indices cannot equal that marker.
This avoids both repeated large-entry swaps during sorting and a separate visited
buffer. The temporary vector is freed before adjacent duplicate hashes and their
RLP buffers are removed. Lookup layout and retained index capacity are unchanged;
peak construction memory includes the temporary vector. Iterators without a
useful size hint may grow the retained index allocation.

Lookups allocate no heap memory, including absence and error paths, and do not
rehash nodes. Each hashed hop performs an `O(log N)` binary search. Cached field
offsets select branch children directly without rescanning prior RLP headers.
Embedded children borrow existing bytes and decode their bounded inline payload.
Traversal is iterative, and key paths remain borrowed nibble views. The index
has no interior mutability and supports concurrent shared reads.

Sparse host benchmarks live in `evm-trie-bench` under the `sparse` feature. They
compare construction and lookup separately with the frozen pre-refactor reader,
check dataset roots against `triehash`, and measure allocation counts in a
separate build. CI asserts correctness and allocation invariants on both hash
backends; timing results are diagnostic, without unstable wall-clock thresholds.

The `test-utils` feature exposes `sparse::reference::hashed_nodes`. This recursive
builder constructs witnesses from complete maps and is checked against
`triehash`; it is an allocating test oracle, not the production lookup algorithm.

## Sparse secure-trie updates

`sparse::PatchTrie` is an isolated mutable overlay over `NodeStore`. Its keys are
exactly 32 bytes, already hashed; it neither hashes keys nor interprets account or
storage values. Values must be nonempty. State-root integration belongs to the
block-execution layer and is not provided by this overlay.

### Updates and canonicalization

- Start from an authenticated root, or the canonical empty root. Unchanged hash
  references need not be revealed, even during finalization.
- Follow borrowed witness nodes until a modification is necessary. Equal-value
  inserts and absent-key removals allocate no overlay nodes or value bytes.
- Split leaves/extensions at the first differing nibble. Branches have no terminal
  value for these fixed-length keys. Reached leaves must exhaust the remaining
  path; reached branches and extensions must leave room for their descendants.
- After deletion, compress unary branches and merge adjoining short paths.
  Compression needs the surviving child's node, not just its hash. A withheld
  sibling returns `BlindedNode`; invalid reached structure returns `MalformedNode`.
- Apply upserts before removals, as in zeth's `SparseState::calculate_state_root`
  and reth's canonical witness generator. This avoids requiring siblings solely
  because of transient branch collapse. A full witness and a minimized witness
  have the same root, but need not support the same intermediate update order.

An update may have changed the overlay before discovering a witness gap. Its
first error is therefore sticky: subsequent updates and `root_hash` return it.
There is no per-operation rollback or full-trie clone. `reset(root)` explicitly
discards both changes and the error, retaining capacity for another trie in the
same immutable store.

### Encoding and memory

Only changed ancestors lose their cached commitments. Finalization visits dirty
nodes bottom-up, using one RLP stream. Encodings shorter than 32 bytes are cached
inline; other nodes retain their Keccak hash. A repeated `root_hash` without
updates performs no encoding, hashing, or allocation. List-completion assertions
guard encoder bugs before reading raw bytes; they do not replace witness checks.

Nodes, branch arrays, and new value bytes occupy separate reusable arenas.
Witness values remain borrowed. Paths use packed 32-byte storage and nibble
offsets, not individually allocated vectors. Obsolete changed nodes/value ranges
remain until reset: this is a batch-oriented overlay, not a long-lived database.
Arena growth can allocate and copy backing buffers; under a bump allocator those
old allocations are not reclaimed. Reusing one overlay for successive storage
tries avoids repeating that growth once capacities suffice. Recursion consumes
at least one nibble per edge and is bounded by the 64-nibble key length.

Tests compare intermediate roots with `triehash`, exercise withheld collapse
siblings, 31/32-byte child encodings, no-op hash/allocation invariants, malformed
paths, and an official EEST v5.4.0 account/storage transition. The isolated RV32
benchmark additionally checks roots against Alloy and measures cold versus reset
arenas; it does not claim end-to-end block execution performance.
