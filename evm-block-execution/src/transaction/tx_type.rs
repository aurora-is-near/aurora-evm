use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// EVM transaction types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TxType {
    /// Legacy transaction (pre-EIP-2718)
    Legacy = 0x00,
    /// EIP-2930: Optional access lists
    Eip2930 = 0x01,
    /// EIP-1559: Fee market change
    Eip1559 = 0x02,
    /// EIP-4844: Shard Blob Transactions
    Eip4844 = 0x03,
    /// EIP-7702: Set EOA account code
    Eip7702 = 0x04,
}

impl From<TxType> for u8 {
    fn from(tx_type: TxType) -> Self {
        match tx_type {
            TxType::Legacy => 0x00,
            TxType::Eip2930 => 0x01,
            TxType::Eip1559 => 0x02,
            TxType::Eip4844 => 0x03,
            TxType::Eip7702 => 0x04,
        }
    }
}

impl TryFrom<u8> for TxType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Legacy),
            0x01 => Ok(Self::Eip2930),
            0x02 => Ok(Self::Eip1559),
            0x03 => Ok(Self::Eip4844),
            0x04 => Ok(Self::Eip7702),
            _ => Err("unknown transaction type"),
        }
    }
}

impl Serialize for TxType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8((*self).into())
    }
}

impl<'de> Deserialize<'de> for TxType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}
