//! The transaction fields that are common to the consensus and the execution form.
//!
//! [`TxPayload`] is everything a transaction says about itself — type, destination, fees, nonce,
//! data and the type-specific extras — with two things deliberately left out:
//!
//! - the **sender**, which is not part of the signed payload but a product of verifying it, and
//! - the **authorization list**, whose shape differs between the two forms (the consensus form
//!   carries signed tuples, the execution form carries recovered authorities).
//!
//! Both [`Transaction`](crate::transaction::Transaction) (execution) and
//! [`SignedTransaction`](crate::transaction::SignedTransaction) (consensus) build on this one
//! payload, so the consensus field set and its order live in a single place.

use crate::transaction::{AccessList, TxKind, TxType};
use primitive_types::U256;

/// Transaction fields shared by the consensus and execution forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPayload {
    /// The transaction type.
    pub tx_type: TxType,

    /// The destination of the transaction.
    pub tx_kind: TxKind,

    /// The maximum amount of gas the transaction can use.
    pub gas_limit: u64,

    /// The value sent to the receiver of [`TxKind::Call`].
    pub value: U256,

    /// The data of the transaction.
    pub data: Vec<u8>,

    /// The nonce of the transaction.
    ///
    /// Note: common field for all transactions.
    pub nonce: U256,

    /// The chain ID of the transaction.
    ///
    /// Incorporated as part of the Spurious Dragon upgrade via [EIP-155]. For a legacy
    /// transaction this field is what distinguishes the two signing forms: `None` means the
    /// signature does **not** cover a chain id (the six-field pre-EIP-155 preimage), `Some` means
    /// it does (the nine-field preimage). Setting it from block configuration rather than from the
    /// transaction's own `v` would therefore change what the signature is checked against.
    ///
    /// [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
    pub chain_id: Option<u64>,

    /// Gas price for the transaction.
    /// Available for legacy transactions, optional for EIP-1559 transactions.
    /// Only before EIP-1559 - London hard fork.
    pub gas_price: Option<U256>,

    /// Maximum fee that can be paid for the transaction.
    /// Available only from EIP-1559 transactions.
    pub max_fee_per_gas: Option<U256>,

    /// Maximum priority fee per gas.
    /// Available only from EIP-1559 transactions.
    pub max_priority_fee_per_gas: Option<U256>,

    /// Access list for the transaction.
    ///
    /// Introduced in EIP-2930.
    pub access_list: AccessList,

    /// Blob versioned hashes, each a 32-byte value.
    /// EIP-4844 transaction field.
    pub blob_versioned_hashes: Vec<U256>,

    /// Max fee per data gas.
    /// EIP-4844 transaction field.
    pub max_fee_per_blob_gas: u128,
}
