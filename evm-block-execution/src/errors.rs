//! Error types for block execution and validation.
//!
//! Errors are layered by scope:
//! - [`InvalidHeader`] — the block environment is inconsistent with the active hardfork;
//! - [`InvalidTransaction`] — a transaction fails pre-execution validation;
//! - [`BlockExecutionError`] — the top level: wraps the two above (via [`InvalidEvmContext`])
//!   and adds block-level execution failures and post-execution header mismatches.

use crate::bloom::Bloom;
use crate::evm_context::InvalidEvmContext;
use aurora_evm::ExitReason;
use core::fmt;
use primitive_types::{H256, U256};

/// Block environment inconsistent with the active hardfork.
///
/// Returned when a [`BlockEnv`](crate::block::BlockEnv) field required by the spec is missing,
/// or a field introduced by a later fork is present.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InvalidHeader {
    /// `prevrandao` is not set for Merge and above.
    PrevrandaoNotSet,
    /// `excess_blob_gas` is not set for Cancun and above.
    ExcessBlobGasNotSet,
    /// `excess_blob_gas` set on a pre-Cancun block (not supported).
    ExcessBlobGasNotSupported,
    /// `blob_versioned_hashes` not supported for pre-Cancun spec.
    BlobVersionedHashesNotSupported,
    /// `max_fee_per_blob_gas` not supported for pre-Cancun spec.
    MaxFeePerBlobGasNotSupported,
    /// A trailing-optional header field is present on a fork that has no such field, or absent on
    /// one that requires it.
    ///
    /// The header's RLP is a mandatory prefix plus a trailing-optional tail, so its *length* alone
    /// says which fields are present — and no fork produces every length in that range. Cancun, for
    /// instance, adds three fields at once, so a 18- or 19-field header belongs to no fork at all
    /// even though it decodes.
    ForkFieldMismatch {
        /// Which field disagrees with the fork.
        field: HeaderField,
        /// Whether the header carries it.
        present: bool,
    },
}

/// A trailing-optional header field, named for reporting a fork disagreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderField {
    /// EIP-1559 base fee (London onward).
    BaseFeePerGas,
    /// EIP-4895 withdrawals root (Shanghai onward).
    WithdrawalsRoot,
    /// EIP-4844 blob gas used (Cancun onward).
    BlobGasUsed,
    /// EIP-4844 excess blob gas (Cancun onward).
    ExcessBlobGas,
    /// EIP-4788 parent beacon block root (Cancun onward).
    ParentBeaconBlockRoot,
    /// EIP-7685 requests hash (Prague onward).
    RequestsHash,
    /// EIP-7928 block access list hash; no fork this crate models carries it.
    BlockAccessListHash,
    /// EIP-7843 slot number; no fork this crate models carries it.
    SlotNumber,
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::BaseFeePerGas => "base_fee_per_gas",
            Self::WithdrawalsRoot => "withdrawals_root",
            Self::BlobGasUsed => "blob_gas_used",
            Self::ExcessBlobGas => "excess_blob_gas",
            Self::ParentBeaconBlockRoot => "parent_beacon_block_root",
            Self::RequestsHash => "requests_hash",
            Self::BlockAccessListHash => "block_access_list_hash",
            Self::SlotNumber => "slot_number",
        };
        f.write_str(name)
    }
}

impl core::error::Error for InvalidHeader {}

impl fmt::Display for InvalidHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrevrandaoNotSet => write!(f, "`prevrandao` not set"),
            Self::ExcessBlobGasNotSet => write!(f, "`excess_blob_gas` not set"),
            Self::ExcessBlobGasNotSupported => {
                write!(f, "`excess_blob_gas` not supported for this spec")
            }
            Self::BlobVersionedHashesNotSupported => {
                write!(f, "`blob_versioned_hashes` not supported for this spec")
            }
            Self::ForkFieldMismatch { field, present } => {
                if *present {
                    write!(f, "`{field}` is set on a fork that has no such field")
                } else {
                    write!(f, "`{field}` is missing on a fork that requires it")
                }
            }
            Self::MaxFeePerBlobGasNotSupported => {
                write!(f, "`max_fee_per_blob_gas` not supported for this spec")
            }
        }
    }
}

/// Transaction rejected by pre-execution validation.
///
/// Produced when a transaction is checked against the block environment, the active spec and the
/// sender account before execution. In block validation any such error makes the whole block
/// invalid.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InvalidTransaction {
    /// Transaction `chain_id` does not match the configured chain id.
    InvalidChainId,
    /// Typed (non-legacy) transaction omits `chain_id`.
    MissingChainId,
    /// Transaction gas limit exceeds the EIP-7825 cap (Osaka and above).
    TxGasLimitGreaterThanCap {
        /// Transaction gas limit.
        gas_limit: u64,
        /// Gas limit cap.
        cap: u64,
    },
    /// Transaction gas limit exceeds the block gas limit.
    CallerGasLimitMoreThanBlock,
    /// EIP-2930 (access list) transaction before Berlin.
    Eip2930NotSupported,
    /// EIP-1559 (dynamic fee) transaction before London.
    Eip1559NotSupported,
    /// Legacy transaction omits `gas_price`.
    InvalidGasPrice,
    /// Fee cap (`gas_price` or `max_fee_per_gas`) is below the block base fee.
    GasPriceLessThanBasefee,
    /// Dynamic-fee transaction omits `max_priority_fee_per_gas`.
    InvalidMaxPriorityFeePerGas,
    /// Dynamic-fee transaction omits `max_fee_per_gas`.
    InvalidMaxFeePerGas,
    /// `max_priority_fee_per_gas` is greater than `max_fee_per_gas`.
    PriorityFeeTooLarge,
    /// EIP-4844 (blob) transaction before Cancun.
    Eip4844NotSupported,
    /// EIP-7702 (set-code) transaction before Prague.
    Eip7702NotSupported,
    /// Legacy transaction carries EIP-1559 fee fields.
    UnexpectedPriorityFeeFields,
    /// A typed (EIP-1559/4844/7702) transaction carries a legacy `gas_price` field.
    UnexpectedGasPriceField,
    /// A non-EIP-4844 transaction carries blob versioned hashes.
    UnexpectedBlobHashes,
    /// A legacy transaction carries an access list, which the type has no field for.
    UnexpectedAccessList,
    /// Block blob gas price exceeds the transaction `max_fee_per_blob_gas`.
    BlobGasPriceGreaterThanMax,
    /// Blob transaction carries no blob versioned hashes.
    EmptyBlobs,
    /// Blob transaction attempts contract creation (forbidden by EIP-4844).
    BlobCreateTransaction,
    /// Blob versioned hash does not start with `VERSIONED_HASH_VERSION_KZG` (`0x01`).
    BlobVersionNotSupported,
    /// Authorization list present on a non-EIP-7702 transaction.
    AuthorizationListNotSupported,
    /// EIP-7702 transaction with an empty authorization list.
    EmptyAuthorizationList,
    /// EIP-7702 transaction attempts contract creation (a `to` address is required).
    Eip7702CreateTransaction,
    /// Intrinsic gas exceeds the transaction gas limit.
    IntrinsicGasMoreThanGasLimit,
    /// EIP-7623 floor gas exceeds the transaction gas limit (Prague and above).
    FloorGasMoreThanGasLimit,
    /// Sender balance cannot cover the maximum cost:
    /// `gas_limit * gas_price + value`, plus the blob fee for blob transactions.
    OutOfFunds,
}

impl core::error::Error for InvalidTransaction {}

impl fmt::Display for InvalidTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChainId => write!(f, "invalid chain id"),
            Self::MissingChainId => write!(f, "missing chain id"),
            Self::TxGasLimitGreaterThanCap { gas_limit, cap } => write!(
                f,
                "transaction gas limit {gas_limit} is greater than the cap {cap}"
            ),
            Self::CallerGasLimitMoreThanBlock => write!(
                f,
                "transaction gas limit is greater than the block gas limit"
            ),
            Self::Eip2930NotSupported => {
                write!(f, "EIP-2930 transaction not supported in this spec")
            }
            Self::Eip1559NotSupported => {
                write!(f, "EIP-1559 transaction not supported in this spec")
            }
            Self::InvalidGasPrice => write!(f, "invalid gas price for legacy transaction"),
            Self::GasPriceLessThanBasefee => write!(
                f,
                "gas price for legacy transaction is less than block base fee"
            ),
            Self::InvalidMaxFeePerGas => {
                write!(f, "invalid max fee per gas for EIP-1559 transaction")
            }
            Self::InvalidMaxPriorityFeePerGas => write!(
                f,
                "invalid max priority fee per gas for EIP-1559 transaction"
            ),
            Self::PriorityFeeTooLarge => write!(
                f,
                "max priority fee per gas is greater than max fee per gas for EIP-1559 transaction"
            ),
            Self::Eip4844NotSupported => {
                write!(f, "EIP-4844 transaction not supported in this spec")
            }
            Self::Eip7702NotSupported => {
                write!(f, "EIP-7702 transaction not supported in this spec")
            }
            Self::UnexpectedPriorityFeeFields => {
                write!(f, "unexpected priority fee fields for legacy transaction")
            }
            Self::UnexpectedGasPriceField => {
                write!(f, "unexpected `gas_price` field for a typed transaction")
            }
            Self::UnexpectedBlobHashes => {
                write!(f, "blob versioned hashes on a non-EIP-4844 transaction")
            }
            Self::UnexpectedAccessList => {
                write!(f, "access list on a legacy transaction")
            }
            Self::BlobGasPriceGreaterThanMax => {
                write!(
                    f,
                    "blob gas price is greater than max fee per blob gas for EIP-4844 transaction"
                )
            }
            Self::EmptyBlobs => {
                write!(f, "blob versioned hashes is empty for EIP-4844 transaction")
            }
            Self::BlobCreateTransaction => {
                write!(
                    f,
                    "EIP-4844 transaction cannot be a contract creation transaction"
                )
            }
            Self::BlobVersionNotSupported => {
                write!(f, "blob version not supported for EIP-4844 transaction")
            }
            Self::AuthorizationListNotSupported => {
                write!(f, "authorization list is not supported for this spec")
            }
            Self::EmptyAuthorizationList => {
                write!(f, "authorization list is empty for EIP-7702 transaction")
            }
            Self::Eip7702CreateTransaction => {
                write!(
                    f,
                    "EIP-7702 transaction cannot be a contract creation transaction"
                )
            }
            Self::IntrinsicGasMoreThanGasLimit => {
                write!(f, "intrinsic gas is greater than the Gas limit")
            }
            Self::FloorGasMoreThanGasLimit => {
                write!(f, "floor gas is greater than the Gas limit")
            }
            Self::OutOfFunds => write!(f, "transaction sender does not have enough funds"),
        }
    }
}

/// Top-level error of block execution and post-execution header validation.
///
/// Aggregates the per-transaction validation layer ([`InvalidEvmContext`]) with block-level
/// execution errors and header-mismatch errors. Every mismatch variant carries the computed
/// (`got`) and expected (`expected`) value for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockExecutionError {
    /// Per-transaction validation failed (header / transaction checks).
    InvalidContext(InvalidEvmContext),
    /// Transaction nonce is different from the sender account nonce.
    InvalidNonce {
        /// Nonce supplied by the transaction.
        tx: U256,
        /// Nonce currently in state.
        state: U256,
    },
    /// Sender has non-empty code that is not an EIP-7702 delegation (EIP-3607).
    SenderHasCode,
    /// EIP-3860: a contract-creation transaction's init code exceeds `MAX_INITCODE_SIZE`
    /// (`2 * MAX_CODE_SIZE = 49152`). Such a transaction is invalid (not merely an execution halt).
    InitCodeTooLarge,
    /// A blob transaction carries more blobs than the active `max_blobs_per_transaction`
    /// (EIP-7594: 6 from Osaka).
    TooManyBlobsInTransaction {
        /// Blob count in the transaction.
        count: u64,
        /// Active per-transaction maximum.
        max: u64,
    },
    /// The block's cumulative blob count exceeds the active `max_blobs_per_block`.
    BlockBlobLimitExceeded {
        /// Cumulative blob count including this transaction.
        count: u64,
        /// Active per-block maximum.
        max: u64,
    },
    /// A transaction's gas limit does not fit in the block's remaining gas.
    BlockGasLimitExceeded {
        /// Transaction gas limit.
        tx_gas_limit: u64,
        /// Gas still available in the block.
        available_gas: u64,
    },
    /// The block timestamp does not fit in a `u64`.
    InvalidBlockTimestamp,
    /// A transaction in the block is invalid, or its execution failed fatally.
    ///
    /// A wrapper carrying the position, because every other variant answers *what* went wrong and
    /// none of them answers *where*. A block is rejected as a whole, so the offending transaction is
    /// the only thing that makes the rejection diagnosable — and the only thing that lets a
    /// disagreement with another client be located. The position is used rather than the transaction
    /// hash: it is free here, whereas the hash would mean re-encoding the transaction to report a
    /// failure. Boxed to keep the enum small.
    Transaction {
        /// Position of the transaction in the block.
        index: usize,
        /// Why the block is invalid.
        source: Box<Self>,
    },
    /// A required pre/post-execution system call failed.
    SystemCallFailed,
    /// EVM execution ended in an unexpected (fatal) state.
    ExecutionFailed(ExitReason),
    /// Computed block gas used does not match the header.
    GasUsedMismatch {
        /// Computed value.
        got: u64,
        /// Header value.
        expected: u64,
    },
    /// Computed receipts root does not match the header.
    ReceiptsRootMismatch {
        /// Computed value.
        got: H256,
        /// Header value.
        expected: H256,
    },
    /// Computed logs bloom does not match the header. Boxed to keep the enum small.
    LogsBloomMismatch {
        /// Computed value.
        got: Box<Bloom>,
        /// Header value.
        expected: Box<Bloom>,
    },
    /// Computed state root does not match the header.
    StateRootMismatch {
        /// Computed value.
        got: H256,
        /// Header value.
        expected: H256,
    },
    /// Computed requests hash does not match the header.
    ///
    /// `Option` on both sides: a fork that has no requests hash and one that has a different value
    /// are different failures, and collapsing them would hide which happened.
    RequestsHashMismatch {
        /// Computed value.
        got: Option<H256>,
        /// Header value.
        expected: Option<H256>,
    },
    /// Computed blob gas used does not match the header.
    BlobGasUsedMismatch {
        /// Computed value.
        got: u64,
        /// Header value.
        expected: u64,
    },
    /// Computed withdrawals root does not match the header.
    ///
    /// `Option` on both sides: an absent list and an empty one are different blocks with different
    /// roots, so presence has to survive into the error.
    WithdrawalsRootMismatch {
        /// Computed value.
        got: Option<H256>,
        /// Header value.
        expected: Option<H256>,
    },
}

impl BlockExecutionError {
    /// Tags an error with the position of the transaction that produced it.
    ///
    /// Idempotent by construction: an error already carrying a position keeps the inner one, so
    /// wrapping twice cannot bury the real cause under a second layer.
    #[must_use]
    pub fn at_transaction(index: usize, source: Self) -> Self {
        if matches!(source, Self::Transaction { .. }) {
            return source;
        }
        Self::Transaction {
            index,
            source: Box::new(source),
        }
    }
}

impl From<InvalidEvmContext> for BlockExecutionError {
    fn from(err: InvalidEvmContext) -> Self {
        Self::InvalidContext(err)
    }
}

impl core::error::Error for BlockExecutionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            // The only variant that wraps another: the position is context, the inner error is the
            // cause, so the chain stays walkable.
            Self::Transaction { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for BlockExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContext(err) => write!(f, "invalid transaction context: {err}"),
            Self::InvalidNonce { tx, state } => {
                write!(f, "invalid nonce: transaction {tx}, state {state}")
            }
            Self::SenderHasCode => write!(f, "sender has non-delegation code (EIP-3607)"),
            Self::InitCodeTooLarge => {
                write!(f, "init code exceeds the maximum size (EIP-3860)")
            }
            Self::TooManyBlobsInTransaction { count, max } => write!(
                f,
                "transaction has {count} blobs, exceeding the per-transaction maximum {max}"
            ),
            Self::BlockBlobLimitExceeded { count, max } => write!(
                f,
                "block blob count {count} exceeds the per-block maximum {max}"
            ),
            Self::BlockGasLimitExceeded {
                tx_gas_limit,
                available_gas,
            } => write!(
                f,
                "transaction gas limit {tx_gas_limit} exceeds the block's remaining gas {available_gas}"
            ),
            Self::InvalidBlockTimestamp => write!(f, "block timestamp does not fit in u64"),
            Self::Transaction { index, source } => {
                write!(
                    f,
                    "transaction at index {index} makes the block invalid: {source}"
                )
            }
            Self::SystemCallFailed => write!(f, "system call failed"),
            Self::ExecutionFailed(reason) => write!(f, "execution failed: {reason:?}"),
            Self::GasUsedMismatch { got, expected } => {
                write!(f, "gas used mismatch: got {got}, expected {expected}")
            }
            Self::ReceiptsRootMismatch { got, expected } => {
                write!(
                    f,
                    "receipts root mismatch: got {got:?}, expected {expected:?}"
                )
            }
            Self::LogsBloomMismatch { .. } => write!(f, "logs bloom mismatch"),
            Self::StateRootMismatch { got, expected } => {
                write!(f, "state root mismatch: got {got:?}, expected {expected:?}")
            }
            Self::RequestsHashMismatch { got, expected } => {
                write!(
                    f,
                    "requests hash mismatch: got {got:?}, expected {expected:?}"
                )
            }
            Self::BlobGasUsedMismatch { got, expected } => {
                write!(f, "blob gas used mismatch: got {got}, expected {expected}")
            }
            Self::WithdrawalsRootMismatch { got, expected } => {
                write!(
                    f,
                    "withdrawals root mismatch: got {got:?}, expected {expected:?}"
                )
            }
        }
    }
}
