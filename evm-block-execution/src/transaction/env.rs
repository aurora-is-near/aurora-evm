//! [`TxEnv`] — everything one transaction contributes to its own execution.
//!
//! The counterpart of [`BlockEnv`](crate::block::BlockEnv): what the interpreter reads about *this*
//! transaction, where `BlockEnv` is what it reads about the block around it. Together they are the
//! whole environment a call runs in.
//!
//! # Not a transaction
//!
//! It carries no signature, and it is not what a block body holds — [`SignedTxEnvelope`] is. Two of
//! its fields are not transaction fields at all but products of *checking* one: `caller` comes from
//! verifying the signature, and `authorization_list` holds authorities already recovered from the
//! EIP-7702 tuples rather than the tuples themselves.
//!
//! That is why building one from a transaction goes through
//! [`SignedTxEnvelope::into_tx_env`](crate::transaction::SignedTxEnvelope::into_tx_env), which takes
//! `caller` as an argument and derives the authorities from the transaction's own tuples. The five
//! per-type `into_tx_env` it dispatches to are public too, for a caller whose transaction type is
//! already known — the envelope adds the dispatch, not the guarantee, and each of the six fills the
//! same fields the same way.
//!
//! All of them **consume** the transaction: by the time one is called the consensus form has no reader
//! left, so its owned fields move here rather than being copied. There is no conversion back.
//!
//! # A union, deliberately
//!
//! The fields are every transaction type's at once, because that is the shape an interpreter wants —
//! one struct read without matching on a type. What a type does not have is present as its absent
//! value (`None`, an empty list, zero).
//!
//! # What the projection guarantees, and where that stops
//!
//! Every `into_tx_env` — the envelope's and the five per-type ones it dispatches to — fills each field
//! from the transaction's own type and writes the rest as their absent values, so a value any of them
//! produces cannot claim a field the transaction never had. Together they are the whole path from
//! consensus data into execution.
//!
//! It does not cover the type itself. The fields are `pub` and there is no constructor that enforces
//! anything, so a value assembled or mutated by hand *can* contradict its own `tx_type` — an access
//! list on a legacy transaction, blob hashes on a non-blob one, a `gas_price` on a dynamic-fee one.
//! Those combinations are rejected by
//! [`EvmContext::validate_tx`](crate::evm_context::EvmContext::validate_tx) before execution, which is
//! where the union is policed rather than prevented.
//!
//! Structural validation cannot reconstruct provenance that this representation deliberately omits:
//! it cannot prove that a hand-written `caller` signed a transaction or that a hand-written recovered
//! authorization came from one of its tuples. A manually assembled [`TxEnv`] is therefore trusted
//! low-level input. The stateless consensus path must obtain it only by pairing a transaction with the
//! sender established by block recovery and calling `SignedTxEnvelope::into_tx_env`.

use crate::transaction::{AccessList, TxKind, TxType};
use aurora_evm::executor::stack::Authorization;
use primitive_types::H160;
use primitive_types::U256;

/// One transaction's execution environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEnv {
    /// The transaction type.
    pub tx_type: TxType,

    /// The sender, established by verifying the signature this environment no longer carries.
    pub caller: H160,

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

    /// Price per gas unit, for the two types that carry one: legacy and EIP-2930.
    ///
    /// `None` for the dynamic-fee types, where it is not merely absent but forbidden — a `gas_price`
    /// beside a fee cap leaves the fee source ambiguous, so `validate_tx` rejects the combination.
    ///
    /// EIP-2930 keeps this field permanently: it predates EIP-1559 but is not superseded by it, so
    /// this is not a pre-London field.
    pub gas_price: Option<U256>,

    /// Total the sender will pay per gas unit, base fee included.
    ///
    /// Carried by every dynamic-fee type — EIP-1559, EIP-4844 and EIP-7702 — and `None` for legacy and
    /// EIP-2930, where `gas_price` takes its place.
    pub max_fee_per_gas: Option<U256>,

    /// Tip paid to the block's beneficiary, on top of the base fee.
    ///
    /// Carried by the same three dynamic-fee types as [`Self::max_fee_per_gas`], and `None` for the
    /// two that price gas with a single number.
    pub max_priority_fee_per_gas: Option<U256>,

    /// Addresses and storage slots pre-warmed for this transaction.
    ///
    /// Introduced by EIP-2930 and carried by every type since, so it is empty only for a legacy
    /// transaction — which has no field for one at all. A non-empty list on a legacy transaction is
    /// rejected before execution rather than charged for, because it is state no signature covered.
    pub access_list: AccessList,

    /// KZG versioned hashes of the blobs this transaction carries, each a 32-byte value.
    ///
    /// EIP-4844 only; empty for every other type, where a non-empty list is rejected before execution.
    /// Widened to `U256` because that is what the executor's vicinity takes, so a hash whose leading
    /// bytes are zero keeps them.
    pub blob_versioned_hashes: Vec<U256>,

    /// Most the sender will pay per unit of blob gas.
    ///
    /// EIP-4844 only, and `0` for every other type — it is not an `Option`, so zero is what absent
    /// means here.
    pub max_fee_per_blob_gas: u128,

    /// Authorities the transaction's EIP-7702 tuples authorise, each already recovered.
    ///
    /// Empty for every other type. Not the signed tuples the transaction carries — those stay on the
    /// consensus form; these are what recovering an authority from each of them produced, one entry per
    /// tuple including the ones that authorise nobody. The count is what intrinsic gas is charged
    /// against, so it must match the tuples exactly; the canonical consensus projection derives this
    /// list instead of accepting it as a separate argument.
    pub authorization_list: Vec<Authorization>,
}
