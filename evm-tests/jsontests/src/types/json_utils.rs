use primitive_types::{H160, H256, U256};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;
use std::str::FromStr;

/// Removes the "0x" prefix from a string if it exists.
pub fn strip_0x_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Converts a hexadecimal string into a `u64` value.
/// Returns an error if the string length is greater than 16 or parsing fails.
pub fn u64_from_str<'de, D: Deserializer<'de>>(value: &str) -> Result<u64, D::Error> {
    if value.len() > 16 {
        return Err(Error::custom(
            format!("u64 value too big (length={})", value.len()).as_str(),
        ));
    }

    u64::from_str_radix(value, 16)
        .map_err(|e| Error::custom(format!("Invalid u64 value: {e}").as_str()))
}

/// Converts a hexadecimal string into a `u8` value.
/// Returns an error if the string length is greater than 16 or parsing fails.
pub fn u8_from_str<'de, D: Deserializer<'de>>(value: &str) -> Result<u8, D::Error> {
    if value.len() > 16 {
        return Err(Error::custom(
            format!("u8 value too big (length={})", value.len()).as_str(),
        ));
    }

    u8::from_str_radix(value, 16)
        .map_err(|e| Error::custom(format!("Invalid u8 value: {e}").as_str()))
}

/// Converts a hexadecimal string into a `U256` value.
/// Returns an error if the string length is greater than 64 or parsing fails.
pub fn u256_from_str<'de, D: Deserializer<'de>>(value: &str) -> Result<U256, D::Error> {
    if value.len() > 64 {
        return Err(Error::custom(
            format!("U256 value too big (length={})", value.len()).as_str(),
        ));
    }

    U256::from_str_radix(value, 16)
        .map_err(|e| Error::custom(format!("Invalid U256 value: {e}").as_str()))
}

/// Converts a hexadecimal string into a `H160` value.
/// Returns an error if the string length is greater than 40 or parsing fails.
pub fn h160_from_str<'de, D: Deserializer<'de>>(value: &str) -> Result<H160, D::Error> {
    if value.len() > 40 {
        return Err(Error::custom(
            format!("H160 value too big (length={})", value.len()).as_str(),
        ));
    }
    H160::from_str(value).map_err(|e| Error::custom(format!("Invalid H160 value: {e}").as_str()))
}

/// Converts a `BTreeMap` with hexadecimal string keys and values into a `BTreeMap` with `U256` keys and values.
/// The hexadecimal strings may optionally start with the "0x" prefix.
/// Returns an error if any key or value cannot be parsed into a U256.
pub fn btree_u256_u256_from_str<'de, D: Deserializer<'de>>(
    map_str: BTreeMap<String, String>,
) -> Result<BTreeMap<U256, U256>, D::Error> {
    let mut map = BTreeMap::new();
    for (k, v) in map_str {
        let key = u256_from_str::<D>(strip_0x_prefix(&k))?;
        let value = u256_from_str::<D>(strip_0x_prefix(&v))?;
        map.insert(key, value);
    }
    Ok(map)
}

/// Converts a `BTreeMap` with hexadecimal string keys and values into a `BTreeMap` with keys and values of type H256.
/// The hexadecimal strings may start with the "0x" prefix, which will be removed.
/// Returns an error if any key or value cannot be converted.
pub fn btree_h256_h256_from_str<'de, D: Deserializer<'de>>(
    map_str: BTreeMap<String, String>,
) -> Result<BTreeMap<H256, H256>, D::Error> {
    let mut map = BTreeMap::new();
    for (k, v) in map_str {
        let key_u256 = u256_from_str::<D>(strip_0x_prefix(&k))?;
        let value_u256 = u256_from_str::<D>(strip_0x_prefix(&v))?;
        let key = H256::from(key_u256.to_big_endian());
        let value = H256::from(value_u256.to_big_endian());
        map.insert(key, value);
    }
    Ok(map)
}

/// Deserializes a hexadecimal string into an H160 address.
/// Returns an error if the string length is greater than 40 or parsing fails.
pub fn deserialize_h160_from_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<H160, D::Error> {
    h160_from_str::<D>(strip_0x_prefix(&String::deserialize(deserializer)?))
}

/// Deserializes a hexadecimal string into an `H256` hash by converting it to `U256` first.
/// Returns an error if parsing fails.
pub fn deserialize_h256_from_u256_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<H256, D::Error> {
    let v = u256_from_str::<D>(strip_0x_prefix(&String::deserialize(deserializer)?))?;
    Ok(H256::from(v.to_big_endian()))
}

/// Deserializes a hexadecimal string into a `U256` value.
/// Returns an error if parsing fails.
pub fn deserialize_u256_from_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<U256, D::Error> {
    u256_from_str::<D>(strip_0x_prefix(&String::deserialize(deserializer)?))
}

/// Deserializes a hexadecimal string into a `u64` value.
/// Returns an error if parsing fails.
#[allow(dead_code)]
pub fn deserialize_u64_from_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    u64_from_str::<D>(strip_0x_prefix(&String::deserialize(deserializer)?))
}

/// Deserializes an optional hexadecimal string into an optional `H256` hash.
/// Returns `None` if the value is missing.
pub fn deserialize_h256_from_u256_str_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<H256>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|s| u256_from_str::<D>(strip_0x_prefix(&s)).map(|v| H256::from(v.to_big_endian())))
        .transpose()
}

/// Deserializes an optional hexadecimal string into an optional `U256` value.
/// Returns `None` if the value is missing.
#[allow(dead_code)]
pub fn deserialize_u256_from_str_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<U256>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|s| u256_from_str::<D>(strip_0x_prefix(&s)))
        .transpose()
}

/// Deserializes an optional hexadecimal string into an optional u64 value.
/// Returns `None` if the value is missing.
pub fn deserialize_u64_from_str_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|s| u64_from_str::<D>(strip_0x_prefix(&s)))
        .transpose()
}

/// Deserializes an optional hexadecimal string into an optional u64 value.
/// Returns `None` if the value is missing.
pub fn deserialize_u8_from_str_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u8>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|s| u8_from_str::<D>(strip_0x_prefix(&s)))
        .transpose()
}

/// Deserializes hexadecimal string into vector of bytes.
/// The hexadecimal string may start with the "0x" prefix.
pub fn deserialize_bytes_from_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    hex::decode(strip_0x_prefix(&s)).map_err(|e: hex::FromHexError| Error::custom(e.to_string()))
}

/// Deserializes a vector of hexadecimal strings into a vector of byte vectors.
/// Each hexadecimal string may start with a "0x" prefix, which will be removed.
/// Returns an error if any string contains invalid hexadecimal characters.
pub fn deserialize_vec_of_hex<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let values: Vec<String> = Vec::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|s| {
            hex::decode(strip_0x_prefix(&s))
                .map_err(|e: hex::FromHexError| Error::custom(e.to_string()))
        })
        .collect()
}

/// Deserializes an optional hexadecimal string into an optional vector of bytes.
/// The hexadecimal string may start with the "0x" prefix.
/// Returns `None` if the value is missing.
pub fn deserialize_bytes_from_str_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|s| {
            hex::decode(strip_0x_prefix(&s))
                .map_err(|e: hex::FromHexError| Error::custom(e.to_string()))
        })
        .transpose()
}

/// Deserializes an optional `JSON` object with hexadecimal string keys and values into an optional
/// `BTreeMap` with `U256` keys and values.
/// The hexadecimal strings may start with the "0x" prefix.
/// Returns `None` if the value is missing.
pub fn deserialize_btree_u256_u256_from_str_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<U256, U256>>, D::Error> {
    Option::<BTreeMap<String, String>>::deserialize(deserializer)?
        .map(btree_u256_u256_from_str::<D>)
        .transpose()
}

/// Deserializes strings to `Vec<U256>`.
pub fn deserialize_vec_u256_from_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<U256>, D::Error> {
    let vec = Vec::<String>::deserialize(deserializer)?;
    vec.into_iter()
        .map(|s| u256_from_str::<D>(strip_0x_prefix(&s)))
        .collect()
}

/// Deserializes strings to `Vec<H256>`.
pub fn deserialize_vec_h256_from_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<H256>, D::Error> {
    let vec = Vec::<String>::deserialize(deserializer)?;
    vec.into_iter()
        .map(|s| {
            let v = u256_from_str::<D>(strip_0x_prefix(&s))?;
            Ok(H256::from(v.to_big_endian()))
        })
        .collect()
}

/// Deserializes an optional hexadecimal string into an optional `H160` address.
/// Returns `None` if the value is missing.
pub fn deserialize_h160_from_str_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<H160>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .filter(|s| !s.is_empty())
        .map(|s| h160_from_str::<D>(strip_0x_prefix(&s)))
        .transpose()
}
