use crate::types::Spec;
use std::path::PathBuf;

#[derive(Default, Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerboseOutput {
    pub verbose: bool,
    pub verbose_failed: bool,
    pub very_verbose: bool,
    pub print_state: bool,
    pub print_slow: bool,
    pub dump_transactions: Option<PathBuf>,
}

#[derive(Default, Debug, Clone)]
pub struct TestConfig {
    pub verbose_output: VerboseOutput,
    pub spec: Option<Spec>,
    pub file_name: PathBuf,
    pub name: String,
}
