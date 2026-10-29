//! Reference MPT builder for test witnesses, checked against `triehash`.
//! Keys are byte paths (prehashed for secure tries); embedded nodes are not listed separately.

use crate::crypto::keccak256;
use std::collections::BTreeMap;

/// Expands each key byte into two nibbles.
fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect()
}

/// Encodes a nibble path with the hex-prefix leaf and parity flags.
fn hex_prefix(path: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 0x20 } else { 0x00 };
    let mut out = if path.len() % 2 == 1 {
        vec![flag | 0x10 | path[0]]
    } else {
        vec![flag]
    };
    let rest = if path.len() % 2 == 1 {
        &path[1..]
    } else {
        path
    };
    out.extend(rest.chunks(2).map(|pair| (pair[0] << 4) | pair[1]));
    out
}

/// Collects the hashed nodes while building.
struct Builder {
    nodes: Vec<Vec<u8>>,
}

impl Builder {
    /// Returns the root hash and all hashed nodes, including the root.
    fn build(items: &BTreeMap<Vec<u8>, Vec<u8>>) -> ([u8; 32], Vec<Vec<u8>>) {
        let mut builder = Self { nodes: Vec::new() };
        let entries: Vec<(Vec<u8>, &[u8])> = items
            .iter()
            .map(|(key, value)| (nibbles(key), value.as_slice()))
            .collect();
        let root = builder.node(&entries, 0);
        let hash = keccak256(&root);
        builder.nodes.push(root);
        (hash, builder.nodes)
    }

    /// Encodes a subtree from sorted keys at the given nibble depth.
    fn node(&mut self, entries: &[(Vec<u8>, &[u8])], depth: usize) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        match entries {
            [] => {
                stream.append_empty_data();
            }
            [(key, value)] => {
                stream.begin_list(2);
                stream.append(&hex_prefix(&key[depth..], true));
                stream.append(value);
            }
            _ => {
                let shared = (depth..entries[0].0.len())
                    .take_while(|&index| {
                        entries
                            .iter()
                            .all(|(key, _)| key.get(index) == entries[0].0.get(index))
                    })
                    .count();
                if shared > 0 {
                    let child = self.node(entries, depth + shared);
                    stream.begin_list(2);
                    stream.append(&hex_prefix(&entries[0].0[depth..depth + shared], false));
                    self.reference(&mut stream, child);
                } else {
                    stream.begin_list(17);
                    for nibble in 0..16u8 {
                        let group: Vec<_> = entries
                            .iter()
                            .filter(|(key, _)| key.get(depth) == Some(&nibble))
                            .cloned()
                            .collect();
                        if group.is_empty() {
                            stream.append_empty_data();
                        } else {
                            let child = self.node(&group, depth + 1);
                            self.reference(&mut stream, child);
                        }
                    }
                    match entries.iter().find(|(key, _)| key.len() == depth) {
                        Some((_, value)) => stream.append(value),
                        None => stream.append_empty_data(),
                    };
                }
            }
        }
        stream.out().to_vec()
    }

    /// Embeds a short child or records its RLP and appends its hash.
    fn reference(&mut self, stream: &mut rlp::RlpStream, child: Vec<u8>) {
        if child.len() < 32 {
            stream.append_raw(&child, 1);
        } else {
            let hash = keccak256(&child);
            self.nodes.push(child);
            stream.append(&hash.as_slice());
        }
    }
}

/// Returns the root hash and hashed witness nodes for `items`, including the root.
#[must_use]
pub fn hashed_nodes(items: &BTreeMap<Vec<u8>, Vec<u8>>) -> ([u8; 32], Vec<Vec<u8>>) {
    Builder::build(items)
}
