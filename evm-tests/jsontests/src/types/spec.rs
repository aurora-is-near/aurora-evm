use serde::de::{self, Unexpected, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

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
                match value {
                    "Frontier" => Ok(Spec::Frontier),
                    "Homestead" | "FrontierToHomesteadAt5" => Ok(Spec::Homestead),
                    "EIP150" | "HomesteadToDaoAt5" | "HomesteadToEIP150At5" => Ok(Spec::Tangerine),
                    "EIP158" => Ok(Spec::SpuriousDragon),
                    "Byzantium" | "EIP158ToByzantiumAt5" => Ok(Spec::Byzantium),
                    "Constantinople"
                    | "ConstantinopleFix"
                    | "ByzantiumToConstantinopleAt5"
                    | "ByzantiumToConstantinopleFixAt5" => Ok(Spec::Constantinople),
                    "Petersburg" => Ok(Spec::Petersburg),
                    "Istanbul" => Ok(Spec::Istanbul),
                    "Berlin" => Ok(Spec::Berlin),
                    "London" | "BerlinToLondonAt5" => Ok(Spec::London),
                    "Merge" | "Paris" => Ok(Spec::Merge),
                    "Shanghai" => Ok(Spec::Shanghai),
                    "Cancun" => Ok(Spec::Cancun),
                    "Prague" => Ok(Spec::Prague),
                    "Osaka" => Ok(Spec::Osaka),
                    _ => Err(de::Error::invalid_value(Unexpected::Str(value), &self)),
                }
            }
        }

        deserializer.deserialize_str(SpecVisitor)
    }
}
