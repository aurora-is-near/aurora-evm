//! Sort compact hash keys, then move each entry through its permutation cycle.

use super::Entry;

/// Big-endian prefixes preserve hash order; native indices avoid narrowing on large inputs.
struct SortKey {
    prefix: u64,
    source: usize,
}

/// Orders entries by the full hash without repeatedly moving their RLP and decode metadata.
pub(super) fn by_hash(nodes: &mut [Entry]) {
    // Also covers empty/singleton inputs and keeps sorted witnesses allocation-free here.
    if nodes.is_sorted_by_key(|entry| entry.hash) {
        return;
    }
    let mut keys: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(source, entry)| SortKey {
            prefix: u64::from_be_bytes([
                entry.hash[0],
                entry.hash[1],
                entry.hash[2],
                entry.hash[3],
                entry.hash[4],
                entry.hash[5],
                entry.hash[6],
                entry.hash[7],
            ]),
            source,
        })
        .collect();
    keys.sort_unstable_by(|a, b| {
        a.prefix
            .cmp(&b.prefix)
            .then_with(|| nodes[a.source].hash.cmp(&nodes[b.source].hash))
    });

    // keys[destination].source is a permutation of 0..nodes.len(). usize::MAX cannot
    // index a slice of Entry and marks completed positions, avoiding a second buffer.
    for start in 0..keys.len() {
        if keys[start].source == usize::MAX {
            continue;
        }
        let mut destination = start;
        loop {
            let source = std::mem::replace(&mut keys[destination].source, usize::MAX);
            if source == start {
                break;
            }
            nodes.swap(destination, source);
            destination = source;
        }
    }
}
