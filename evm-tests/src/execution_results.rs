use crate::types::Spec;
use aurora_evm::backend::{Apply, Basic, MemoryAccount};
use aurora_evm::executor::stack::Authorization;
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct FailedTestDetails {
    pub name: String,
    pub spec: Spec,
    pub index: usize,
    pub expected_hash: H256,
    pub actual_hash: H256,
    pub state: BTreeMap<H160, MemoryAccount>,
}

#[derive(Clone, Debug)]
pub struct TestExecutionResult {
    pub total: u64,
    pub failed: u64,
    pub failed_tests: Vec<FailedTestDetails>,
    pub bench: Vec<TestBench>,
    pub dump_successful_txs: Vec<RawInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawInput {
    pub spec: RawSpec,
    pub caller: H160,
    pub value: U256,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub access_list: Vec<(H160, Vec<H256>)>,
    pub authorization_list: Vec<Authorization>,
    pub apply_values: Vec<RawApply>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RawApply {
    Modify {
        address: H160,
        basic: Basic,
        code: Option<Vec<u8>>,
        storage: Vec<(H256, H256)>,
        reset_storage: bool,
    },
    Delete {
        address: H160,
    },
}

impl<I> From<Apply<I>> for RawApply
where
    I: IntoIterator<Item = (H256, H256)>,
{
    fn from(value: Apply<I>) -> Self {
        match value {
            Apply::Modify {
                address,
                basic,
                code,
                storage,
                reset_storage,
            } => Self::Modify {
                address,
                basic,
                code,
                storage: storage.into_iter().collect(),
                reset_storage,
            },
            Apply::Delete { address } => Self::Delete { address },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RawSpec {
    Frontier,
    Homestead,
    TangerineWhistle,
    SpuriousDragon,
    Byzantium,
    Constantinople,
    Petersburg,
    Istanbul,
    Berlin,
    London,
    Merge,
    Shanghai,
    Cancun,
    Prague,
    Osaka,
}

impl From<Spec> for RawSpec {
    fn from(spec: Spec) -> Self {
        match spec {
            Spec::Frontier => Self::Frontier,
            Spec::Homestead => Self::Homestead,
            Spec::Tangerine => Self::TangerineWhistle,
            Spec::SpuriousDragon => Self::SpuriousDragon,
            Spec::Byzantium => Self::Byzantium,
            Spec::Constantinople => Self::Constantinople,
            Spec::Petersburg => Self::Petersburg,
            Spec::Istanbul => Self::Istanbul,
            Spec::Berlin => Self::Berlin,
            Spec::London => Self::London,
            Spec::Merge => Self::Merge,
            Spec::Shanghai => Self::Shanghai,
            Spec::Cancun => Self::Cancun,
            Spec::Prague => Self::Prague,
            Spec::Osaka => Self::Osaka,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TestBench {
    pub name: String,
    pub spec: Spec,
    pub elapsed: Duration,
}

impl TestExecutionResult {
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            total: 0,
            failed: 0,
            failed_tests: Vec::new(),
            bench: Vec::new(),
            dump_successful_txs: Vec::new(),
        }
    }

    pub fn merge(&mut self, src: Self) {
        self.failed_tests.extend(src.failed_tests);
        self.total += src.total;
        self.failed += src.failed;

        for bench in src.bench {
            self.set_benchmark(bench);
        }

        self.dump_successful_txs.extend(src.dump_successful_txs);
    }

    pub fn set_benchmark(&mut self, bench: TestBench) {
        if self.bench.is_empty() {
            self.bench.push(bench);
            return;
        }

        if self.bench.len() < 100 {
            self.bench.push(bench);
            return;
        }

        // If has smaller elapsed than all existing then skip
        if !self.bench.iter().any(|b| bench.elapsed > b.elapsed) {
            return;
        }

        let mut min_idx = 0usize;
        let mut min_elapsed = self.bench[0].elapsed;
        for (i, b) in self.bench.iter().enumerate().skip(1) {
            if b.elapsed < min_elapsed {
                min_elapsed = b.elapsed;
                min_idx = i;
            }
        }

        if bench.elapsed > min_elapsed {
            self.bench[min_idx] = bench;
        }
    }

    pub fn print_bench(&self) {
        let mut items = self.bench.clone();
        items.sort_unstable_by(|a, b| b.elapsed.cmp(&a.elapsed));

        if items.is_empty() {
            return;
        }

        let formatted: Vec<(String, String, String)> = items
            .iter()
            .map(|b| {
                let elapsed_str = format!("{:.6}s", b.elapsed.as_secs_f64());
                let spec_str = format!("{:?}", b.spec);
                let name_str = b.name.clone();
                (elapsed_str, spec_str, name_str)
            })
            .collect();

        let mut w_elapsed = 0usize;
        let mut w_spec = 0usize;
        let mut w_name = 0usize;
        for (e, s, n) in &formatted {
            w_elapsed = w_elapsed.max(e.len());
            w_spec = w_spec.max(s.len());
            w_name = w_name.max(n.len());
        }

        let bold_on = "\x1b[1m";
        let gray_on = "\x1b[90m";
        let reset = "\x1b[0m";

        for (e, s, n) in formatted {
            let e_pad = format!("{e:w_elapsed$}");
            let s_pad = format!("{s:w_spec$}");
            let n_pad = format!("{n:w_name$}");
            println!("{bold_on}{e_pad}{reset}  {gray_on}{s_pad}{reset}  {n_pad}",);
        }
    }
}
