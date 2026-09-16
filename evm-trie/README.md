# Aurora EVM ordered trie

`aurora-evm-trie` builds Ethereum ordered Merkle-Patricia roots for the keys
`RLP(0..len)`. It is a small production dependency shared by block execution and
the RV32 benchmark guest. It does not pull in EVM precompiles, `blst`, `c-kzg`, or
their native builds.

The public API has two paths:

- `ordered_trie_root`: borrows already encoded values.
- `ordered_trie_root_with_encoder`: encodes each item once in reusable RLP scratch,
  consuming the borrowed result before the next item is encoded.

Key order is `1..=127, 0, 128..`, truncated to the collection size. The index
ranges determine branch and extension paths without sorting or storing keys.
Non-root nodes are inlined only when their **entire RLP** is shorter than 32 bytes;
the root is always hashed. Empty input returns the canonical empty root.

## Algorithm and sources

The [algorithm documentation](ALGORITHM.md) explains the dense-index traversal,
correctness invariants, and derivation of the scratch bounds and stack tiers.
The underlying RLP, hex-prefix, and MPT rules are specified in the
[Yellow Paper, Appendices B–D](https://ethereum.github.io/yellowpaper/paper.pdf).
[Alloy 0.9.5](https://docs.rs/alloy-trie/0.9.5/src/alloy_trie/root.rs.html)
provides a reference for the same RLP-index ordering and reusable encoder pattern;
the interval decomposition and scratch layout are specific to this builder.

## Memory and limits

Node scratch is bounded by native key depth, not value size. Through 65,536 items
it uses stack arrays; larger collections use one depth-sized heap buffer. Large
leaf values are fed directly to Keccak instead of copied into a node-sized buffer.
Small inline leaves still copy their bounded payloads.

The encoder path additionally owns one reusable `RlpStream`. Its capacity may grow
with the largest encoded item and list nesting; it does not retain one allocation
per leaf. Empty input does not construct this stream. Stack memory, hash state,
input data and guest paging are not zero just because the builder avoids heap
allocation.

Only ordered keys are supported. Secure state/storage roots remain in
`evm-block-execution` on `triehash`; this is not a sparse witness trie.

## Hash backend

The default backend is `sha3` Keccak-256, as in block execution before this change.
The optional `tiny-keccak` feature selects the same primitive through that crate.
RISC Zero acceleration additionally requires the guest's pinned `tiny-keccak`
patch; the feature alone is not an acceleration guarantee. No VM-specific backend
is silently enabled in normal block execution.

Both backends are checked against independent `triehash`/`sha3` roots:

```sh
cargo test -p aurora-evm-trie --release
cargo test -p aurora-evm-trie --release --all-features
```

Official EEST commitments are exercised by the block-execution trie test in
`evm-block-execution/src/trie/tests/ordered_roots.rs`. Reproducible comparisons and guest
commands live in [evm-trie-bench](../evm-trie-bench/README.md).
