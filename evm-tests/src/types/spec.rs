use aurora_evm::Config;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Spec {
    /// Frontier hard fork
    /// Activated at block 0
    Frontier,
    /// Homestead hard fork
    /// Activated at block 1150000
    Homestead,
    /// Tangerine Whistle hard fork
    /// Activated at block 2463000
    Tangerine,
    /// Spurious Dragon hard fork
    /// Activated at block 2675000
    SpuriousDragon,
    /// Byzantium hard fork
    /// Activated at block 4370000
    Byzantium,
    /// Constantinople hard fork
    /// Activated at block 7280000 is overwritten with PETERSBURG
    Constantinople,
    /// Petersburg hard fork
    /// Activated at block 7280000
    Petersburg,
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
    pub const fn is_filtered_spec_for_skip(&self) -> bool {
        matches!(
            self,
            Self::Tangerine
                | Self::SpuriousDragon
                | Self::Frontier
                | Self::Homestead
                | Self::Byzantium
                | Self::Constantinople
                | Self::Istanbul
                | Self::Berlin
        )
    }

    #[must_use]
    pub const fn get_gasometer_config(&self) -> Option<Config> {
        match self {
            Self::Istanbul => Some(Config::istanbul()),
            Self::Berlin => Some(Config::berlin()),
            Self::London => Some(Config::london()),
            Self::Merge => Some(Config::merge()),
            Self::Shanghai => Some(Config::shanghai()),
            Self::Cancun => Some(Config::cancun()),
            Self::Prague => Some(Config::prague()),
            Self::Osaka => Some(Config::osaka()),
            _ => None,
        }
    }
}

impl FromStr for Spec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Frontier" => Ok(Self::Frontier),
            "Homestead" | "FrontierToHomesteadAt5" => Ok(Self::Homestead),
            "EIP150" | "HomesteadToDaoAt5" | "HomesteadToEIP150At5" => Ok(Self::Tangerine),
            "EIP158" => Ok(Self::SpuriousDragon),
            "Byzantium" | "EIP158ToByzantiumAt5" => Ok(Self::Byzantium),
            "Constantinople"
            | "ConstantinopleFix"
            | "ByzantiumToConstantinopleAt5"
            | "ByzantiumToConstantinopleFixAt5" => Ok(Self::Constantinople),
            "Petersburg" => Ok(Self::Petersburg),
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
