/// The semantic kind of an Ethereum transaction.
///
/// Not an EIP-2718 wire byte: a legacy transaction has no type prefix. Envelope and receipt codecs
/// map the typed variants to their owning EIP module's `TYPE_BYTE` explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxType {
    /// Legacy transaction (pre-EIP-2718)
    Legacy,
    /// EIP-2930: Optional access lists
    Eip2930,
    /// EIP-1559: Fee market change
    Eip1559,
    /// EIP-4844: Shard Blob Transactions
    Eip4844,
    /// EIP-7702: Set EOA account code
    Eip7702,
}
