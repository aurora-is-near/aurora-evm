use serde::Deserialize;

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, Deserialize)]
pub struct Info {
    pub hash: String,
    pub comment: String,
    #[serde(rename = "filling-transition-tool")]
    pub filling_transition_tool: String,
    pub description: String,
    pub url: String,
    pub fixture_format: String,
    #[serde(rename = "reference-spec")]
    pub reference_spec: String,
    #[serde(rename = "reference-spec-version")]
    pub reference_spec_version: String,
    #[serde(rename = "eels-resolution")]
    pub eels_resolution: EelsResolution,
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, Deserialize)]
pub struct EelsResolution {
    #[serde(rename = "git-url")]
    pub git_url: String,
    pub branch: String,
    pub commit: String,
}
