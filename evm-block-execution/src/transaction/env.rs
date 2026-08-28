//! Execution-oriented transaction environment.
//!
//! [`TxEnv`] is the transaction counterpart of [`BlockEnv`](crate::block::BlockEnv). Unlike the
//! signed consensus representation ([`crate::transaction::SignedTxEnvelope`]), it is a union of
//! every transaction type's fields and carries no signature. Missing fields use canonical absent
//! values (`None`, zero or an empty list), allowing the interpreter to read one structure without
//! dispatching on the type.
//!
//! [`SignedTxEnvelope::into_tx_env`](crate::transaction::SignedTxEnvelope::into_tx_env) consumes the
//! consensus value so owned data moves rather than clones. It also receives the recovered `caller`
//! and derives EIP-7702 authorities from the signed tuples.
//!
//! This is an opaque trusted projection: its fields are crate-private, so callers cannot invent a
//! prevalidated EIP-7702 authority or create contradictory type fields. Projection receives the
//! recovered `caller`; consensus code must obtain it from block recovery rather than trust a hint.

use crate::transaction::{TxKind, TxType};
use aurora_evm::executor::stack::Authorization;
use primitive_types::{H160, H256, U256};

/// One transaction's execution environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEnv {
    /// The transaction type.
    pub(crate) tx_type: TxType,

    /// The sender recovered from the signature this environment no longer carries.
    pub(crate) caller: H160,

    /// The destination of the transaction.
    pub(crate) tx_kind: TxKind,

    /// The maximum amount of gas the transaction can use.
    pub(crate) gas_limit: u64,

    /// The value sent to the receiver of [`TxKind::Call`].
    pub(crate) value: U256,

    /// The data of the transaction.
    pub(crate) data: Vec<u8>,

    /// The transaction nonce.
    pub(crate) nonce: U256,

    /// The chain ID of the transaction.
    ///
    /// For legacy transactions, `None` selects the six-field pre-EIP-155 signing form; `Some`
    /// selects the nine-field EIP-155 form. It must therefore come from the transaction's `v`, not
    /// from block configuration.
    ///
    /// [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
    pub(crate) chain_id: Option<u64>,

    /// Price per gas unit, for the two types that carry one: legacy and EIP-2930.
    ///
    /// `None` for dynamic-fee types, where combining it with fee caps is rejected as ambiguous.
    pub(crate) gas_price: Option<U256>,

    /// Total price cap per gas, base fee included; `None` for legacy and EIP-2930.
    pub(crate) max_fee_per_gas: Option<U256>,

    /// Priority-fee cap for dynamic-fee types; `None` for legacy and EIP-2930.
    pub(crate) max_priority_fee_per_gas: Option<U256>,

    /// Addresses and storage slots pre-warmed for this transaction, in Aurora EVM's tuple form.
    ///
    /// Present from EIP-2930 onward. A non-empty list on a legacy transaction is rejected.
    pub(crate) access_list: Vec<(H160, Vec<H256>)>,

    /// KZG versioned hashes of the blobs this transaction references, each a 32-byte value.
    ///
    /// EIP-4844 only; widened to `U256` for the executor without losing leading zero bytes.
    pub(crate) blob_versioned_hashes: Vec<U256>,

    /// Most the sender will pay per unit of blob gas.
    ///
    /// EIP-4844 only; zero is the absent value for other types.
    pub(crate) max_fee_per_blob_gas: u128,

    /// Authorities the transaction's EIP-7702 tuples authorise, each already recovered.
    ///
    /// One recovered entry per signed tuple, including invalid tuples, because intrinsic gas depends
    /// on the tuple count. Empty for other transaction types.
    pub(crate) authorization_list: Vec<Authorization>,
}
