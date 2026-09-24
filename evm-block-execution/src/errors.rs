//! Error types for block execution and validation.
//!
//! Errors are layered by scope:
//!
//! - [`InvalidHeader`] — the block environment is inconsistent with the active hardfork;
//! - [`InvalidTransaction`] — a transaction fails pre-execution validation;
//! - [`BlockExecutionError`] — the top level: wraps the two above (via [`InvalidEvmContext`])
//!   and adds block-level execution failures and post-execution header mismatches.

use crate::bloom::Bloom;
use crate::eips::eip6110::DepositLogError;
use crate::evm_context::InvalidEvmContext;
use crate::witness_backend::WitnessDbError;
use aurora_evm::ExitReason;
use core::fmt;
use primitive_types::{H160, H256, U256};

/// Block environment inconsistent with the active hardfork.
///
/// Returned when a [`BlockEnv`](crate::block::BlockEnv) field required by the spec is missing,
/// or a field introduced by a later fork is present.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InvalidHeader {
    /// `prevrandao` is not set for Merge and above.
    PrevrandaoNotSet,
    /// `base_fee_per_gas` is not set for London and above.
    BaseFeeNotSet,
    /// `excess_blob_gas` is not set for Cancun and above.
    ExcessBlobGasNotSet,
    /// `excess_blob_gas` set on a pre-Cancun block (not supported).
    ExcessBlobGasNotSupported,
    /// `blob_versioned_hashes` not supported for pre-Cancun spec.
    BlobVersionedHashesNotSupported,
    /// `max_fee_per_blob_gas` not supported for pre-Cancun spec.
    MaxFeePerBlobGasNotSupported,
    /// A trailing-optional header field is present while an earlier one is absent.
    ///
    /// Positional RLP cannot represent a gap: encoding would shift every later field. This is
    /// invalid independently of the selected fork.
    TrailingFieldGap {
        /// The first field present while the one before it is absent.
        field: HeaderField,
    },
}

/// A trailing-optional header field, named for validation errors.
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
            Self::BaseFeeNotSet => write!(f, "`base_fee_per_gas` not set"),
            Self::ExcessBlobGasNotSet => write!(f, "`excess_blob_gas` not set"),
            Self::ExcessBlobGasNotSupported => {
                write!(f, "`excess_blob_gas` not supported for this spec")
            }
            Self::BlobVersionedHashesNotSupported => {
                write!(f, "`blob_versioned_hashes` not supported for this spec")
            }
            Self::TrailingFieldGap { field } => {
                write!(f, "`{field}` is set while an earlier trailing field is not")
            }
            Self::MaxFeePerBlobGasNotSupported => {
                write!(f, "`max_fee_per_blob_gas` not supported for this spec")
            }
        }
    }
}

/// Transaction rejected by pre-execution validation.
///
/// Covers checks against the block, active spec and sender account. Any variant invalidates the
/// containing block.
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
/// Combines transaction validation, execution failures and post-execution header mismatches.
/// Mismatch variants carry computed (`got`) and header (`expected`) values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockExecutionError {
    /// Per-transaction validation failed (header / transaction checks).
    InvalidContext(InvalidEvmContext),
    /// Transaction nonce differs from the sender account nonce or is at least `u64::MAX` (EIP-2681).
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
    /// No Cancun-or-later fork is active at the block timestamp.
    ActiveSpecUnavailable {
        /// Timestamp whose execution fork could not be resolved.
        timestamp: u64,
    },
    /// A transaction in the block is invalid, or its execution failed fatally.
    ///
    /// Adds the offending transaction's position to another error. Uses an index to avoid hashing
    /// the transaction on the error path; boxed to keep the enum small.
    Transaction {
        /// Position of the transaction in the block.
        index: usize,
        /// Why the block is invalid.
        source: Box<Self>,
    },
    /// The header's `excess_blob_gas` yields a blob gas price that does not fit in `u128`.
    BlobGasPriceOverflow {
        /// The header value.
        excess_blob_gas: u64,
    },
    /// A Cancun-or-later block carries no `parent_beacon_block_root` for the EIP-4788 call.
    MissingParentBeaconBlockRoot,
    /// A post-execution request contract (EIP-7002 / EIP-7251) has no code.
    SystemContractEmpty {
        /// The predeploy address.
        address: H160,
    },
    /// The EIP-7002 withdrawal-requests contract call reverted or failed.
    WithdrawalRequestsContractCall {
        /// How the call ended.
        reason: ExitReason,
    },
    /// The EIP-7251 consolidation-requests contract call reverted or failed.
    ConsolidationRequestsContractCall {
        /// How the call ended.
        reason: ExitReason,
    },
    /// A deposit-contract log is not a canonically encoded deposit event (EIP-6110).
    DepositRequestDecode(DepositLogError),
    /// Execution read state the witness did not prove.
    MissingWitness(WitnessDbError),
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
    /// Both sides retain presence, distinguishing a missing field from a mismatched value.
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
    /// Both sides retain presence because an absent list differs from an empty one.
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
    /// Already-positioned errors are returned unchanged.
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

impl From<DepositLogError> for BlockExecutionError {
    fn from(err: DepositLogError) -> Self {
        Self::DepositRequestDecode(err)
    }
}

impl From<WitnessDbError> for BlockExecutionError {
    fn from(missing: WitnessDbError) -> Self {
        Self::MissingWitness(missing)
    }
}

impl core::error::Error for BlockExecutionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            // Preserve the underlying cause through the positional wrapper.
            Self::Transaction { source, .. } => Some(source),
            Self::DepositRequestDecode(source) => Some(source),
            Self::MissingWitness(source) => Some(source),
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
            Self::ActiveSpecUnavailable { timestamp } => {
                write!(
                    f,
                    "no supported execution fork is active at timestamp {timestamp}"
                )
            }
            Self::Transaction { index, source } => {
                write!(
                    f,
                    "transaction at index {index} makes the block invalid: {source}"
                )
            }
            Self::BlobGasPriceOverflow { excess_blob_gas } => write!(
                f,
                "blob gas price for excess blob gas {excess_blob_gas} overflows u128"
            ),
            Self::MissingParentBeaconBlockRoot => {
                write!(
                    f,
                    "missing parent beacon block root for the EIP-4788 system call"
                )
            }
            Self::SystemContractEmpty { address } => {
                write!(f, "system contract {address:?} has no code")
            }
            Self::WithdrawalRequestsContractCall { reason } => {
                write!(f, "withdrawal requests contract call failed: {reason:?}")
            }
            Self::ConsolidationRequestsContractCall { reason } => {
                write!(f, "consolidation requests contract call failed: {reason:?}")
            }
            Self::DepositRequestDecode(_) => write!(f, "invalid deposit contract log"),
            Self::MissingWitness(_) => write!(f, "execution read state the witness did not prove"),
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
