//! EVM state types

use crate::{
    bytes::Bytes,
    hash::{Address, Bloom, H256},
};
use serde::Deserialize;

/// State log deserialization.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct Log {
    /// Address.
    pub address: Address,
    /// Topics.
    pub topics: Vec<H256>,
    /// Data.
    pub data: Bytes,
    /// Bloom.
    pub bloom: Bloom,
}

#[cfg(test)]
mod tests {
    use super::Log;

    #[test]
    fn log_deserialization() {
        let s = r#"{
			"address" : "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6",
			"bloom" : "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008800000000000000000020000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000",
			"data" : "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"topics" : [
				"0000000000000000000000000000000000000000000000000000000000000000"
			]
		}"#;
        let _deserialized: Log = serde_json::from_str(s).unwrap();
        // TODO: validate all fields
    }
}
