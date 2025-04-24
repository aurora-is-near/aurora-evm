use primitive_types::{H160, H256, U256};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::str::FromStr;

/// Removes the "0x" prefix from a string if it exists.
fn strip_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Converts a hexadecimal string into a u64 value.
/// Returns an error if the string length is greater than 16 or parsing fails.
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

/// Converts a hexadecimal string into a U256 value.
/// Returns an error if the string length is greater than 64 or parsing fails.
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

/// Deserializes a hexadecimal string into an H160 address.
/// Returns an error if the string length is greater than 40 or parsing fails.
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

/// Deserializes a hexadecimal string into an H256 hash by converting it to U256 first.
/// Returns an error if parsing fails.
#[allow(dead_code)]
pub fn deserialize_h256_from_u256_str<'de, D>(deserializer: D) -> Result<H256, D::Error>
where
    D: Deserializer<'de>,
{
    let v = u256_from_str::<D>(strip_prefix(&String::deserialize(deserializer)?))?;
    Ok(H256::from(v.to_big_endian()))
}

/// Deserializes a hexadecimal string into a U256 value.
/// Returns an error if parsing fails.
pub fn deserialize_u256_from_str<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    u256_from_str::<D>(strip_prefix(&String::deserialize(deserializer)?))
}

/// Deserializes a hexadecimal string into a u64 value.
/// Returns an error if parsing fails.
#[allow(dead_code)]
pub fn deserialize_u64_from_str<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    u64_from_str::<D>(strip_prefix(&String::deserialize(deserializer)?))
}

/// Deserializes an optional hexadecimal string into an optional H256 hash.
/// Returns None if the value is missing.
pub fn deserialize_h256_from_u256_str_opt<'de, D>(deserializer: D) -> Result<Option<H256>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|s| u256_from_str::<D>(strip_prefix(&s)).map(|v| H256::from(v.to_big_endian())))
        .transpose()
}

/// Deserializes an optional hexadecimal string into an optional U256 value.
/// Returns None if the value is missing.
#[allow(dead_code)]
pub fn deserialize_u256_from_str_opt<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|s| u256_from_str::<D>(strip_prefix(&s)))
        .transpose()
}

/// Deserializes an optional hexadecimal string into an optional u64 value.
/// Returns None if the value is missing.
pub fn deserialize_u64_from_str_opt<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|s| u64_from_str::<D>(strip_prefix(&s)))
        .transpose()
}
