use crate::bloom::Bloom;
use crate::evm_context::InvalidEvmContext;
use aurora_evm::ExitReason;
use core::fmt;
use primitive_types::{H256, U256};

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InvalidHeader {
    /// `prevrandao` is not set for Merge and above.
    PrevrandaoNotSet,
    /// `excess_blob_gas` is not set for Cancun and above.
    ExcessBlobGasNotSet,
    /// `blob_versioned_hashes` not supported for pre-Cancun spec.
    BlobVersionedHashesNotSupported,
    /// `max_fee_per_blob_gas` not supported for pre-Cancun spec.
    MaxFeePerBlobGasNotSupported,
}

impl core::error::Error for InvalidHeader {}

impl fmt::Display for InvalidHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrevrandaoNotSet => write!(f, "`prevrandao` not set"),
            Self::ExcessBlobGasNotSet => write!(f, "`excess_blob_gas` not set"),
            Self::BlobVersionedHashesNotSupported => {
                write!(f, "`blob_versioned_hashes` not supported for this spec")
            }
            Self::MaxFeePerBlobGasNotSupported => {
                write!(f, "`max_fee_per_blob_gas` not supported for this spec")
            }
        }
    }
}

/// Transaction validation error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InvalidTransaction {
    InvalidChainId,
    MissingChainId,
    /// Transaction gas limit is greater than the cap.
    TxGasLimitGreaterThanCap {
        /// Transaction gas limit.
        gas_limit: u64,
        /// Gas limit cap.
        cap: u64,
    },
    CallerGasLimitMoreThanBlock,
    Eip2930NotSupported,
    Eip1559NotSupported,
    InvalidGasPrice,
    GasPriceLessThanBasefee,
    InvalidMaxPriorityFeePerGas,
    InvalidMaxFeePerGas,
    PriorityFeeTooLarge,
    Eip4844NotSupported,
    Eip7702NotSupported,
    UnexpectedPriorityFeeFields,
    BlobGasPriceGreaterThanMax,
    EmptyBlobs,
    BlobCreateTransaction,
    BlobVersionNotSupported,
    TooManyBlobs(usize),
    AuthorizationListNotSupported,
    EmptyAuthorizationList,
    Eip7702CreateTransaction,
    IntrinsicGasMoreThanGasLimit,
    FloorGasMoreThanGasLimit,
    OutOfFunds,
    CallerNotFound,
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
            Self::TooManyBlobs(msx) => {
                write!(
                    f,
                    "too many blobs in EIP-4844 transaction, maximum allowed is {msx}",
                )
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
            Self::CallerNotFound => write!(f, "transaction sender not found in state"),
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
    /// Transaction nonce is greater than the sender account nonce.
    NonceTooHigh {
        /// Nonce supplied by the transaction.
        tx: U256,
        /// Nonce currently in state.
        state: U256,
    },
    /// Transaction nonce is lower than the sender account nonce.
    NonceTooLow {
        /// Nonce supplied by the transaction.
        tx: U256,
        /// Nonce currently in state.
        state: U256,
    },
    /// Sender has non-empty code that is not an EIP-7702 delegation (EIP-3607).
    SenderHasCode,
    /// Cumulative gas used exceeds the block gas limit.
    BlockGasLimitExceeded {
        /// Cumulative gas used so far.
        gas_used: u64,
        /// Block gas limit.
        gas_limit: u64,
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
    RequestsHashMismatch {
        /// Computed value.
        got: H256,
        /// Header value.
        expected: H256,
    },
    /// Computed blob gas used does not match the header.
    BlobGasUsedMismatch {
        /// Computed value.
        got: u64,
        /// Header value.
        expected: u64,
    },
    /// Computed withdrawals root does not match the header.
    WithdrawalsRootMismatch {
        /// Computed value.
        got: H256,
        /// Header value.
        expected: H256,
    },
}

impl From<InvalidEvmContext> for BlockExecutionError {
    fn from(err: InvalidEvmContext) -> Self {
        Self::InvalidContext(err)
    }
}

impl core::error::Error for BlockExecutionError {}

impl fmt::Display for BlockExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContext(err) => write!(f, "invalid transaction context: {err}"),
            Self::NonceTooHigh { tx, state } => {
                write!(f, "nonce too high: transaction {tx}, state {state}")
            }
            Self::NonceTooLow { tx, state } => {
                write!(f, "nonce too low: transaction {tx}, state {state}")
            }
            Self::SenderHasCode => write!(f, "sender has non-delegation code (EIP-3607)"),
            Self::BlockGasLimitExceeded {
                gas_used,
                gas_limit,
            } => write!(f, "block gas used {gas_used} exceeds gas limit {gas_limit}"),
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

#[cfg(test)]
mod tests {
    use super::{BlockExecutionError, InvalidTransaction};
    use crate::evm_context::InvalidEvmContext;
    use primitive_types::{H256, U256};

    #[test]
    fn from_invalid_context_wraps() {
        let ctx = InvalidEvmContext::InvalidTransaction(InvalidTransaction::OutOfFunds);
        let err: BlockExecutionError = ctx.into();
        assert!(matches!(err, BlockExecutionError::InvalidContext(_)));
        assert!(err.to_string().contains("invalid transaction context"));
    }

    #[test]
    fn mismatch_carries_got_and_expected() {
        let err = BlockExecutionError::StateRootMismatch {
            got: H256::zero(),
            expected: H256::repeat_byte(0x11),
        };
        assert!(err.to_string().contains("state root mismatch"));
        // A matching pair is a different value than a mismatching one (Eq works).
        let other = BlockExecutionError::StateRootMismatch {
            got: H256::repeat_byte(0x11),
            expected: H256::repeat_byte(0x11),
        };
        assert_ne!(err, other);
    }

    #[test]
    fn nonce_error_displays() {
        let err = BlockExecutionError::NonceTooHigh {
            tx: U256::from(5u64),
            state: U256::from(3u64),
        };
        assert!(err.to_string().contains("nonce too high"));
    }

    #[test]
    fn block_level_errors_display() {
        let err = BlockExecutionError::BlobGasUsedMismatch {
            got: 1,
            expected: 2,
        };
        assert!(err.to_string().contains("blob gas used mismatch"));
        let err = BlockExecutionError::BlockGasLimitExceeded {
            gas_used: 100,
            gas_limit: 50,
        };
        assert!(err.to_string().contains("exceeds gas limit"));
        assert!(BlockExecutionError::SenderHasCode
            .to_string()
            .contains("EIP-3607"));
    }
}
