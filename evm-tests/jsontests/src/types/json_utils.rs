use primitive_types::{H160, H256, U256};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::str::FromStr;

fn strip_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn u64_from_str<'de, D>(value: &str) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    if value.len() > 16 {
        return Err(Error::custom(
            format!("u64 value too big (length={})", value.len()).as_str(),
        ));
    }

    u64::from_str_radix(value, 16)
        .map_err(|e| Error::custom(format!("Invalid u64 value: {e}").as_str()))
}

fn u256_from_str<'de, D>(value: &str) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    if value.len() > 64 {
        return Err(Error::custom(
            format!("U256 value too big (length={})", value.len()).as_str(),
        ));
    }

    U256::from_str_radix(value, 16)
        .map_err(|e| Error::custom(format!("Invalid U256 value: {e}").as_str()))
}

pub fn deserialize_h160_from_str<'de, D>(deserializer: D) -> Result<H160, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let value = strip_prefix(&s);
    if value.len() > 40 {
        return Err(Error::custom(
            format!("H160 value too big (length={})", value.len()).as_str(),
        ));
    }
    H160::from_str(value).map_err(|e| Error::custom(format!("Invalid H160 value: {e}").as_str()))
}

pub fn deserialize_h256_from_u256_str<'de, D>(deserializer: D) -> Result<H256, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let v = u256_from_str::<D>(strip_prefix(&s))?;
    Ok(H256::from(v.to_big_endian()))
}

pub fn deserialize_u256_from_str<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u256_from_str::<D>(strip_prefix(&s))
}

pub fn deserialize_u64_from_str<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u64_from_str::<D>(strip_prefix(&s))
}

pub fn deserialize_h256_from_u256_str_opt<'de, D>(deserializer: D) -> Result<Option<H256>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => u256_from_str::<D>(strip_prefix(&s))
            .map(|v| Some(H256::from(v.to_big_endian())))
            .map_err(Error::custom),
        None => Ok(None),
    }
}

pub fn deserialize_u256_from_str_opt<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => u256_from_str::<D>(strip_prefix(&s))
            .map(Some)
            .map_err(Error::custom),
        None => Ok(None),
    }
}

pub fn deserialize_u64_from_str_opt<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => u64_from_str::<D>(strip_prefix(&s))
            .map(Some)
            .map_err(Error::custom),
        None => Ok(None),
    }
}
