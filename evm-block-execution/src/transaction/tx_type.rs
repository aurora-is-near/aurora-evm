//! Semantic transaction kinds used after envelope decoding.

/// The semantic kind of an Ethereum transaction.
///
/// Not an EIP-2718 wire byte: a legacy transaction has no type prefix. Envelope and receipt codecs
/// map the typed variants to their owning EIP module's `TYPE_BYTE` explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxType {
    /// Legacy transaction (pre-EIP-2718).
    Legacy,
    /// EIP-2930 access-list transaction.
    Eip2930,
    /// EIP-1559 dynamic-fee transaction.
    Eip1559,
    /// EIP-4844 blob transaction.
    Eip4844,
    /// EIP-7702 set-code transaction.
    Eip7702,
}
