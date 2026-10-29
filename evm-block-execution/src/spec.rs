//! Hardfork identifiers and their Aurora EVM gas configurations.

use aurora_evm::Config;
use core::str::FromStr;

/// Ethereum execution hardfork supported by this crate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Spec {
    /// Istanbul.
    Istanbul,
    /// Berlin.
    Berlin,
    /// London.
    London,
    /// Paris / the Merge.
    Merge,
    /// Shanghai.
    Shanghai,
    /// Cancun.
    Cancun,
    /// Prague.
    Prague,
    /// Osaka.
    Osaka,
}

impl Spec {
    /// Returns the Aurora EVM gasometer configuration for this hardfork.
    #[must_use]
    pub const fn get_gasometer_config(&self) -> Config {
        match self {
            Self::Istanbul => Config::istanbul(),
            Self::Berlin => Config::berlin(),
            Self::London => Config::london(),
            Self::Merge => Config::merge(),
            Self::Shanghai => Config::shanghai(),
            Self::Cancun => Config::cancun(),
            Self::Prague => Config::prague(),
            Self::Osaka => Config::osaka(),
        }
    }
}

impl FromStr for Spec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Istanbul" => Ok(Self::Istanbul),
            "Berlin" => Ok(Self::Berlin),
            "London" | "BerlinToLondonAt5" => Ok(Self::London),
            "Merge" | "Paris" => Ok(Self::Merge),
            "Shanghai" => Ok(Self::Shanghai),
            "Cancun" => Ok(Self::Cancun),
            "Prague" => Ok(Self::Prague),
            "Osaka" => Ok(Self::Osaka),
            _ => Err(format!("Unknown Spec value: {value}")),
        }
    }
}
