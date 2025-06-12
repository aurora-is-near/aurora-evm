use crate::types::spec::Spec;
use std::path::PathBuf;

#[derive(Default, Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerboseOutput {
    pub verbose: bool,
    pub verbose_failed: bool,
    pub very_verbose: bool,
    pub print_state: bool,
}

#[derive(Default, Debug, Clone)]
pub struct TestConfig {
    pub verbose_output: VerboseOutput,
    pub spec: Option<Spec>,
    pub file_name: PathBuf,
}
