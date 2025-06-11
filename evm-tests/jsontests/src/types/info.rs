use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub comment: String,
    #[serde(default, rename = "filling-rpc-server")]
    pub filling_rpc_server: Option<String>,
    #[serde(rename = "filling-tool-version")]
    pub filling_tool_version: Option<String>,
    #[serde(rename = "fixture-format", alias = "fixture_format")]
    pub fixture_format: Option<String>,
    #[serde(rename = "generatedTestHash")]
    pub generated_test_hash: Option<String>,
    pub lllcversion: Option<String>,
    pub solidity: Option<String>,
    pub source: Option<String>,
    #[serde(rename = "sourceHash")]
    pub source_hash: Option<String>,
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "filling-transition-tool")]
    pub filling_transition_tool: Option<String>,
    pub hash: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "reference-spec")]
    pub reference_spec: Option<String>,
    #[serde(rename = "reference-spec-version")]
    pub reference_spec_version: Option<String>,
    #[serde(rename = "eels-resolution")]
    pub eels_resolution: Option<EelsResolution>,
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, Deserialize)]
pub struct EelsResolution {
    #[serde(rename = "git-url")]
    pub git_url: String,
    pub branch: String,
    pub commit: String,
}
