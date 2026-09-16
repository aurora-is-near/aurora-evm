//! Extracts a deterministic, size-stratified corpus from the official EEST release.

use aurora_evm_block_execution::block::Block;
use aurora_evm_trie_bench::{Case, IMPLEMENTATIONS};
use std::{
    collections::BTreeSet,
    error::Error,
    path::{Path, PathBuf},
};

fn files(dir: &Path, output: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            files(&path, output)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            output.push(path);
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or("usage: corpus EEST_DIRECTORY OUTPUT_JSON")?,
    );
    let output = args.next().ok_or("missing output path")?;
    let mut paths = Vec::new();
    files(&root.join("blockchain_tests"), &mut paths)?;
    if paths.is_empty() {
        return Err("no blockchain fixture files found".into());
    }
    paths.sort();
    let mut selected = Vec::new();
    let mut strata = BTreeSet::new();
    let (mut negative, mut unsupported, mut checked) = (0, 0, 0);
    for path in paths {
        let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        for (name, test) in json.as_object().ok_or("fixture is not an object")? {
            let blocks = test["blocks"].as_array().ok_or("fixture has no blocks")?;
            for (index, block) in blocks.iter().enumerate() {
                if block.get("expectException").is_some() {
                    negative += 1;
                    continue;
                }
                let raw = block["rlp"].as_str().ok_or("positive block has no RLP")?;
                let bytes = hex::decode(raw.trim_start_matches("0x"))?;
                let decoded = match Block::decode_exact(&bytes) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        unsupported += 1;
                        continue;
                    }
                };
                let source = format!("{}::{name}#{index}", path.strip_prefix(&root)?.display());
                let txs = decoded
                    .transactions()
                    .iter()
                    .map(|tx| tx.encoded_2718())
                    .collect::<Vec<_>>();
                let mut groups = vec![("transactions", decoded.header.transactions_root.0, txs)];
                if let Some(withdrawals) = decoded.body.withdrawals() {
                    groups.push((
                        "withdrawals",
                        decoded
                            .header
                            .withdrawals_root
                            .ok_or("withdrawals root missing")?
                            .0,
                        withdrawals
                            .iter()
                            .map(|w| rlp::encode(w).to_vec())
                            .collect(),
                    ));
                }

                for (kind, expected, values) in groups {
                    let slices = values.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    for (implementation, calculate) in IMPLEMENTATIONS {
                        if calculate(&slices) != expected {
                            return Err(
                                format!("{implementation}: {source} {kind} root mismatch").into()
                            );
                        }
                    }
                    checked += 1;
                    if strata.insert((kind, values.len())) {
                        selected.push(Case {
                            source: source.clone(),
                            kind: kind.into(),
                            root: hex::encode(expected),
                            values: values.iter().map(hex::encode).collect(),
                        });
                    }
                }
            }
        }
    }
    if !strata
        .iter()
        .any(|&(kind, count)| kind == "transactions" && count >= 129)
    {
        return Err("corpus lacks the RLP index-width boundary".into());
    }
    if unsupported != 0 {
        return Err(format!(
            "{unsupported} positive blocks failed decoding; refusing an incomplete corpus"
        )
        .into());
    }

    eprintln!(
        "checked={checked}, selected={}, negative_blocks={negative}, unsupported_positive_blocks={unsupported}",
        selected.len()
    );

    std::fs::write(output, serde_json::to_vec_pretty(&selected)?)?;
    Ok(())
}
