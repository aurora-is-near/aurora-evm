use std::fmt;

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
                write!(
                    f,
                    "authorization list is empty for transaction with non-empty access list"
                )
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
