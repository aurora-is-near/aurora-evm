use aurora_evm::Config;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Spec {
    /// Istanbul hard fork
    /// Activated at block 9069000
    Istanbul,
    /// Berlin hard fork
    /// Activated at block 12244000
    Berlin,
    /// London hard fork
    /// Activated at block 12965000
    London,
    /// Paris/Merge hard fork
    /// Activated at block 15537394 (TTD: 58750000000000000000000)
    Merge,
    /// Shanghai hard fork
    /// Activated at block 17034870 (Timestamp: 1681338455)
    Shanghai,
    /// Cancun hard fork
    /// Activated at block 19426587 (Timestamp: 1710338135)
    Cancun,
    /// Prague hard fork
    /// Activated at block 22431084 (Timestamp: 1746612311)
    Prague,
    /// Osaka hard fork
    /// Activated at block TBD
    Osaka,
}

impl Spec {
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
impl<'de> Deserialize<'de> for Spec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SpecVisitor;

        impl Visitor<'_> for SpecVisitor {
            type Value = Spec;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Ethereum hard fork name")
            }

            fn visit_str<E>(self, value: &str) -> Result<Spec, E>
            where
                E: de::Error,
            {
                Spec::from_str(value)
                    .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(value), &self))
            }
        }

        deserializer.deserialize_str(SpecVisitor)
    }
}
