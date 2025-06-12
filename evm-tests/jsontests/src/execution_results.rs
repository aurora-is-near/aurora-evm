use crate::types::spec::Spec;
use aurora_evm::backend::MemoryAccount;
use primitive_types::{H160, H256};
use std::collections::BTreeMap;

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
}

impl TestExecutionResult {
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            total: 0,
            failed: 0,
            failed_tests: Vec::new(),
        }
    }

    pub fn merge(&mut self, src: Self) {
        self.failed_tests.extend(src.failed_tests);
        self.total += src.total;
        self.failed += src.failed;
    }
}
