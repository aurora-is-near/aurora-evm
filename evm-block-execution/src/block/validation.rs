//! Parent-relative and pre-execution consensus validation for post-merge blocks.
//!
//! Validation follows pipeline: standalone header rules, rules against the verified
//! parent, then body commitments. This crate supports Cancun-or-later blocks only.
//! The block codec also accepts earlier forks, but this validator intentionally rejects them.

use crate::block::{BlockBody, Header, RecoveredBlock, SealedHeader};
use crate::chain_spec::{ActiveSpec, ChainSpec};
use crate::constants::EMPTY_OMMER_ROOT_HASH;
use crate::eips::eip1559::{BaseFeeParams, GAS_LIMIT_BOUND_DIVISOR};
use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::eips::eip7840::BlobParams;
use crate::errors::HeaderField;
use crate::spec::Spec;
use crate::transaction::{SignedTxEnvelope, TxType};
use crate::trie::ordered_trie_root_with_encoder;
use core::fmt;
use primitive_types::{H256, U256};

#[cfg(test)]
mod tests;

/// Maximum `extra_data` length permitted by the Yellow Paper.
const MAX_EXTRA_DATA_SIZE: usize = 32;
/// Minimum block gas limit.
const MINIMUM_GAS_LIMIT: u64 = 5_000;
/// Protocol maximum block gas limit (`2^63 - 1`).
const MAXIMUM_GAS_LIMIT: u64 = 0x7fff_ffff_ffff_ffff;
/// EIP-7934 maximum canonical block RLP length, active from Osaka.
const MAX_RLP_BLOCK_SIZE: usize = 8_388_608;

/// Validates a recovered block before execution.
///
/// The supplied parent must be the verified parent derived from the execution witness.
/// On success, returns the timestamp-resolved execution context.
///
/// # Errors
/// [`BlockValidationError`] if the header, parent transition or body commitments are invalid.
#[inline]
pub fn validate_block_consensus(
    chain_spec: &ChainSpec,
    block: &RecoveredBlock,
    parent: &SealedHeader,
) -> Result<ActiveSpec, BlockValidationError> {
    let active_spec = validate_header(chain_spec, block.header())?;
    validate_header_against_parent(block.sealed_header(), parent, chain_spec, &active_spec)?;
    validate_block_pre_execution(block, &active_spec)?;

    Ok(active_spec)
}

/// Resolves the Cancun-or-later execution context and validates standalone header rules.
///
/// Checks post-Merge constants, generic bounds, fork-specific fields, and EIP-4844 blob limits.
/// Parent transitions and body commitments are validated separately.
#[inline]
fn validate_header(
    chain_spec: &ChainSpec,
    header: &Header,
) -> Result<ActiveSpec, BlockValidationError> {
    let active_spec = chain_spec
        .active_spec_at_timestamp(header.timestamp)
        .ok_or(BlockValidationError::CancunNotActive {
            timestamp: header.timestamp,
        })?;

    validate_post_merge_fields(header)?;
    validate_header_extra_data(header)?;
    validate_header_gas(header)?;
    validate_header_base_fee(header)?;
    validate_header_withdrawals_root(header)?;
    validate_header_cancun_standalone(header, active_spec.blob_params())?;
    validate_header_requests_hash(header, active_spec.spec())?;

    // TODO: related to Amsterdam hard fork
    validate_unsupported_header_fields(header)?;

    Ok(active_spec)
}

/// Validates the fixed post-Merge fields required by EIP-3675.
///
/// Proof-of-stake headers have zero difficulty and nonce, and commit to an empty ommers list.
#[inline]
fn validate_post_merge_fields(header: &Header) -> Result<(), BlockValidationError> {
    if !header.difficulty.is_zero() {
        return Err(BlockValidationError::DifficultyNotZero {
            difficulty: header.difficulty,
        });
    }

    if header.nonce != [0; 8] {
        return Err(BlockValidationError::NonceNotZero {
            nonce: header.nonce,
        });
    }

    if header.ommers_hash != EMPTY_OMMER_ROOT_HASH {
        return Err(BlockValidationError::OmmersHashNotEmpty {
            found: header.ommers_hash,
        });
    }

    Ok(())
}

/// Validates the Yellow Paper's 32-byte `extra_data` limit.
#[inline]
const fn validate_header_extra_data(header: &Header) -> Result<(), BlockValidationError> {
    if header.extra_data.len() > MAX_EXTRA_DATA_SIZE {
        return Err(BlockValidationError::ExtraDataTooLong {
            len: header.extra_data.len(),
            max: MAX_EXTRA_DATA_SIZE,
        });
    }

    Ok(())
}

/// Validates the standalone header gas bounds.
///
/// Reported gas use must fit the block limit; equality with executed gas is checked post-execution.
#[inline]
const fn validate_header_gas(header: &Header) -> Result<(), BlockValidationError> {
    if header.gas_used > header.gas_limit {
        return Err(BlockValidationError::GasUsedExceedsGasLimit {
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
        });
    }

    if header.gas_limit > MAXIMUM_GAS_LIMIT {
        return Err(BlockValidationError::GasLimitExceedsMaximum {
            gas_limit: header.gas_limit,
            max: MAXIMUM_GAS_LIMIT,
        });
    }

    Ok(())
}

/// Requires the EIP-1559 base fee introduced by London.
///
/// This validator accepts Cancun-or-later blocks, so the field is always required.
#[inline]
const fn validate_header_base_fee(header: &Header) -> Result<(), BlockValidationError> {
    if header.base_fee_per_gas.is_none() {
        return Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::BaseFeePerGas,
            present: false,
        });
    }

    Ok(())
}

/// Requires the EIP-4895 withdrawals root introduced by Shanghai.
///
/// This validator accepts Cancun-or-later blocks, so the field is always required.
#[inline]
const fn validate_header_withdrawals_root(header: &Header) -> Result<(), BlockValidationError> {
    if header.withdrawals_root.is_none() {
        return Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::WithdrawalsRoot,
            present: false,
        });
    }

    Ok(())
}

/// Validates the Cancun header fields that need no parent.
///
/// The EIP-4844 blob fields and the EIP-4788 parent beacon root must be present, and
/// `blob_gas_used` must be an integral number of blobs within the active schedule's block limit.
#[inline]
const fn validate_header_cancun_standalone(
    header: &Header,
    blob_params: BlobParams,
) -> Result<(), BlockValidationError> {
    let Some(blob_gas_used) = header.blob_gas_used else {
        return Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::BlobGasUsed,
            present: false,
        });
    };

    if header.parent_beacon_block_root.is_none() {
        return Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::ParentBeaconBlockRoot,
            present: false,
        });
    }

    if header.excess_blob_gas.is_none() {
        return Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::ExcessBlobGas,
            present: false,
        });
    }

    if !blob_gas_used.is_multiple_of(DATA_GAS_PER_BLOB) {
        return Err(BlockValidationError::BlobGasUsedNotMultiple { blob_gas_used });
    }

    let max = blob_params.max_blob_gas_per_block();
    if blob_gas_used > max {
        return Err(BlockValidationError::BlobGasUsedExceedsMaximum { blob_gas_used, max });
    }

    Ok(())
}

/// Requires the EIP-7685 requests hash from Prague and rejects it before activation.
#[inline]
const fn validate_header_requests_hash(
    header: &Header,
    active_spec: Spec,
) -> Result<(), BlockValidationError> {
    let prague_active = match active_spec {
        Spec::Prague | Spec::Osaka => true,
        Spec::Istanbul
        | Spec::Berlin
        | Spec::London
        | Spec::Merge
        | Spec::Shanghai
        | Spec::Cancun => false,
    };

    if prague_active {
        if header.requests_hash.is_none() {
            return Err(BlockValidationError::ForkFieldMismatch {
                field: HeaderField::RequestsHash,
                present: false,
            });
        }
    } else if header.requests_hash.is_some() {
        return Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::RequestsHash,
            present: true,
        });
    }

    Ok(())
}

/// Rejects EIP-7928 and EIP-7843 fields, which activate after the latest supported fork.
#[inline]
const fn validate_unsupported_header_fields(header: &Header) -> Result<(), BlockValidationError> {
    if header.block_access_list_hash.is_some() {
        return Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::BlockAccessListHash,
            present: true,
        });
    }
    if header.slot_number.is_some() {
        return Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::SlotNumber,
            present: true,
        });
    }

    Ok(())
}

/// Validates the current header against its parent.
#[inline]
fn validate_header_against_parent(
    header: &SealedHeader,
    parent: &SealedHeader,
    chain_spec: &ChainSpec,
    active_spec: &ActiveSpec,
) -> Result<(), BlockValidationError> {
    let parent_hash = parent.hash();

    validate_against_parent_hash_number(header, parent_hash, parent.number)?;
    validate_against_parent_timestamp(header.timestamp, parent.timestamp)?;
    validate_gas_limit_against_parent(header.gas_limit, parent.gas_limit)?;

    validate_against_parent_eip1559_base_fee(header, parent, chain_spec.base_fee_params)?;

    validate_against_parent_4844(header, parent, active_spec)?;

    Ok(())
}

/// Validates the EIP-4844 header fields against the parent block.
///
/// The `excess_blob_gas` field must exist in the child header and match the value calculated from
/// the parent header fields.
#[inline]
fn validate_against_parent_4844(
    header: &SealedHeader,
    parent: &SealedHeader,
    active_spec: &ActiveSpec,
) -> Result<(), BlockValidationError> {
    // `header.blob_gas_used` is not re-checked here: `validate_header_cancun_standalone` binds it
    // earlier in the pipeline, so a second check would be unreachable. The reference repeats it
    // because its `validate_against_parent_4844` is a public, self-contained entry point.
    let excess_blob_gas =
        header
            .excess_blob_gas
            .ok_or(BlockValidationError::ForkFieldMismatch {
                field: HeaderField::ExcessBlobGas,
                present: false,
            })?;
    // At the Cancun transition the parent has no blob fields; EIP-4844 defines both as zero.
    let expected_excess_blob_gas = active_spec
        .blob_params()
        .next_block_excess_blob_gas(
            parent.excess_blob_gas.unwrap_or(0),
            parent.blob_gas_used.unwrap_or(0),
            parent.base_fee_per_gas.unwrap_or(0),
        )
        .ok_or(BlockValidationError::ExcessBlobGasTransitionUnavailable)?;
    if excess_blob_gas != expected_excess_blob_gas {
        return Err(BlockValidationError::ExcessBlobGasMismatch {
            header: excess_blob_gas,
            expected: expected_excess_blob_gas,
        });
    }

    Ok(())
}

/// Validates the base fee against the parent and EIP-1559 rules.
#[inline]
fn validate_against_parent_eip1559_base_fee(
    header: &SealedHeader,
    parent: &SealedHeader,
    base_fee_params: BaseFeeParams,
) -> Result<(), BlockValidationError> {
    let base_fee = header
        .base_fee_per_gas
        .ok_or(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::BaseFeePerGas,
            present: false,
        })?;
    let expected_base_fee = parent
        .next_block_base_fee(base_fee_params)
        .ok_or(BlockValidationError::BaseFeeTransitionUnavailable)?;
    if base_fee != expected_base_fee {
        return Err(BlockValidationError::BaseFeeMismatch {
            header: base_fee,
            expected: expected_base_fee,
        });
    }

    Ok(())
}

/// Validates against the parent hash and number.
///
/// This function ensures that the header block number is sequential and that the hash of the parent
/// header matches the parent hash in the header.
#[inline]
fn validate_against_parent_hash_number(
    header: &SealedHeader,
    parent_hash: H256,
    parent_number: u64,
) -> Result<(), BlockValidationError> {
    if header.parent_hash != parent_hash {
        return Err(BlockValidationError::ParentHashMismatch {
            header: header.parent_hash,
            parent: parent_hash,
        });
    }
    // Check if parent number is consistent.
    if parent_number.checked_add(1) != Some(header.number) {
        return Err(BlockValidationError::ParentNumberMismatch {
            parent: parent_number,
            child: header.number,
        });
    }

    Ok(())
}

/// Validates that the block timestamp is greater than the parent block timestamp.
#[inline]
const fn validate_against_parent_timestamp(
    header_timestamp: u64,
    parent_timestamp: u64,
) -> Result<(), BlockValidationError> {
    if header_timestamp <= parent_timestamp {
        return Err(BlockValidationError::TimestampNotAfterParent {
            parent: parent_timestamp,
            child: header_timestamp,
        });
    }

    Ok(())
}

/// Validates the EIP-1559 gas-limit ramp and minimum.
#[inline]
const fn validate_gas_limit_against_parent(
    gas_limit: u64,
    parent_gas_limit: u64,
) -> Result<(), BlockValidationError> {
    let bound = parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR;
    // Check for an increase in gas limit beyond the allowed threshold.
    if gas_limit > parent_gas_limit {
        if gas_limit - parent_gas_limit >= bound {
            return Err(BlockValidationError::GasLimitInvalidIncrease {
                parent: parent_gas_limit,
                child: gas_limit,
            });
        }
    }
    // Check for a decrease in gas limit beyond the allowed threshold.
    else if parent_gas_limit - gas_limit >= bound {
        return Err(BlockValidationError::GasLimitInvalidDecrease {
            parent: parent_gas_limit,
            child: gas_limit,
        });
    }
    // Check if the self gas limit is below the minimum required limit.
    if gas_limit < MINIMUM_GAS_LIMIT {
        return Err(BlockValidationError::GasLimitBelowMinimum {
            gas_limit,
            min: MINIMUM_GAS_LIMIT,
        });
    }

    Ok(())
}

/// Body-derived values needed by pre-execution validation.
struct BodyMetrics {
    transactions_root: H256,
    withdrawals_root: Option<H256>,
    blob_gas_used: u64,
    block_rlp_length: usize,
}

/// Checks canonical RLP lengths before hashing, then encodes each leaf into reusable scratch.
///
/// On Osaka, the growing encoded body is size-checked before either trie is built.
fn calculate_body_metrics(
    header: &Header,
    body: &BlockBody,
    active_spec: Spec,
) -> Result<BodyMetrics, BlockValidationError> {
    let header_length = rlp::encode(header).len();

    let withdrawals_length = match body.withdrawals() {
        Some(withdrawals) => {
            let mut payload_length = 0usize;
            for withdrawal in withdrawals {
                payload_length = payload_length
                    .checked_add(withdrawal.encoded_length())
                    .ok_or(BlockValidationError::ArithmeticOverflow)?;

                if active_spec >= Spec::Osaka {
                    let withdrawals_length = rlp_container_length(payload_length)?;
                    let rlp_length =
                        calculate_block_rlp_length(header_length, 0, withdrawals_length)?;
                    validate_block_size(rlp_length, active_spec)?;
                }
            }
            rlp_container_length(payload_length)?
        }
        None => 0,
    };

    let mut transactions_payload_length = 0usize;
    let mut blob_count = 0u64;
    for transaction in &body.transactions {
        let envelope_length = transaction
            .encoded_2718_length()
            .ok_or(BlockValidationError::ArithmeticOverflow)?;
        let block_item_length = if transaction.tx_type() == TxType::Legacy {
            envelope_length
        } else {
            rlp_container_length(envelope_length)?
        };
        transactions_payload_length = transactions_payload_length
            .checked_add(block_item_length)
            .ok_or(BlockValidationError::ArithmeticOverflow)?;

        if let SignedTxEnvelope::Eip4844(transaction) = transaction {
            let count =
                u64::try_from(transaction.tx.blob_versioned_hashes.len()).unwrap_or(u64::MAX);
            blob_count = blob_count
                .checked_add(count)
                .ok_or(BlockValidationError::ArithmeticOverflow)?;
        }
        if active_spec >= Spec::Osaka {
            let rlp_length = calculate_block_rlp_length(
                header_length,
                transactions_payload_length,
                withdrawals_length,
            )?;
            validate_block_size(rlp_length, active_spec)?;
        }
    }

    let block_rlp_length = calculate_block_rlp_length(
        header_length,
        transactions_payload_length,
        withdrawals_length,
    )?;

    let transactions_root =
        ordered_trie_root_with_encoder(&body.transactions, |transaction, stream| {
            let encoded = transaction.encode_2718_in(stream);
            // Catch drift between the EIP-7934 length preflight and the wire encoder in debug builds.
            debug_assert_eq!(transaction.encoded_2718_length(), Some(encoded.len()));
            encoded
        });
    let withdrawals_root = body.withdrawals().map(|withdrawals| {
        ordered_trie_root_with_encoder(withdrawals, crate::withdrawal::Withdrawal::encode_in)
    });
    let blob_gas_used = blob_count
        .checked_mul(DATA_GAS_PER_BLOB)
        .ok_or(BlockValidationError::ArithmeticOverflow)?;

    Ok(BodyMetrics {
        transactions_root,
        withdrawals_root,
        blob_gas_used,
        block_rlp_length,
    })
}

/// Calculates the canonical block-list length from already measured body components.
fn calculate_block_rlp_length(
    header_length: usize,
    transactions_payload_length: usize,
    withdrawals_length: usize,
) -> Result<usize, BlockValidationError> {
    let transactions_length = rlp_container_length(transactions_payload_length)?;
    let block_payload_length = header_length
        .checked_add(transactions_length)
        // The body model has no ommers, so its encoded list is the one-byte empty list.
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(withdrawals_length))
        .ok_or(BlockValidationError::ArithmeticOverflow)?;

    rlp_container_length(block_payload_length)
}

/// Returns an RLP container length, reporting unrepresentable aggregates as a block error.
fn rlp_container_length(payload_length: usize) -> Result<usize, BlockValidationError> {
    crate::rlp_strict::list_length(payload_length).ok_or(BlockValidationError::ArithmeticOverflow)
}

/// Validates body commitments and fork-specific body rules from one metrics pass.
#[inline]
fn validate_block_pre_execution(
    block: &RecoveredBlock,
    active_spec: &ActiveSpec,
) -> Result<(), BlockValidationError> {
    let header = block.header();
    let spec = active_spec.spec();
    let metrics = calculate_body_metrics(header, block.body(), spec)?;

    // NOTE: Ommers match by construction - the codec requires an empty list and header validation
    // requires its canonical root.

    // EIP-4895: Beacon chain push withdrawals as operations
    validate_shanghai_withdrawals(header.withdrawals_root, metrics.withdrawals_root)?;
    validate_cancun_gas(header.blob_gas_used, metrics.blob_gas_used)?;
    // Applies EIP-7934 from Osaka onward.
    validate_block_size(metrics.block_rlp_length, spec)?;

    validate_transactions_root(header.transactions_root, metrics.transactions_root)
}

/// Validates EIP-4895 withdrawals presence and root.
#[inline]
fn validate_shanghai_withdrawals(
    header_root: Option<H256>,
    computed_root: Option<H256>,
) -> Result<(), BlockValidationError> {
    // Header validation already requires this field for every supported fork. Recheck it here so
    // this commitment validator remains fail-closed if the surrounding pipeline is rearranged.
    let header = header_root.ok_or(BlockValidationError::ForkFieldMismatch {
        field: HeaderField::WithdrawalsRoot,
        present: false,
    })?;

    match computed_root {
        Some(computed) if header != computed => {
            Err(BlockValidationError::WithdrawalsRootMismatch { header, computed })
        }
        Some(_) => Ok(()),
        None => Err(BlockValidationError::WithdrawalsPresenceMismatch {
            header: true,
            body: false,
        }),
    }
}

/// Validates EIP-4844 blob gas against the block body.
#[inline]
fn validate_cancun_gas(
    header_blob_gas_used: Option<u64>,
    computed: u64,
) -> Result<(), BlockValidationError> {
    let header = header_blob_gas_used.ok_or(BlockValidationError::ForkFieldMismatch {
        field: HeaderField::BlobGasUsed,
        present: false,
    })?;
    if computed != header {
        return Err(BlockValidationError::BlobGasUsedMismatch { header, computed });
    }

    Ok(())
}

/// Validates the transactions trie commitment.
#[inline]
fn validate_transactions_root(header: H256, computed: H256) -> Result<(), BlockValidationError> {
    if computed != header {
        return Err(BlockValidationError::TransactionsRootMismatch { header, computed });
    }

    Ok(())
}

/// Applies EIP-7934 from Osaka onward.
#[inline]
fn validate_block_size(rlp_length: usize, active_spec: Spec) -> Result<(), BlockValidationError> {
    if active_spec >= Spec::Osaka && rlp_length > MAX_RLP_BLOCK_SIZE {
        return Err(BlockValidationError::BlockTooLarge {
            rlp_length,
            max: MAX_RLP_BLOCK_SIZE,
        });
    }

    Ok(())
}

/// Why a block fails pre-execution consensus validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockValidationError {
    /// Cancun is not active at the block timestamp under the configured fork boundary.
    CancunNotActive { timestamp: u64 },
    /// A post-merge header has non-zero difficulty.
    DifficultyNotZero { difficulty: U256 },
    /// A post-merge header has a non-zero nonce.
    NonceNotZero { nonce: [u8; 8] },
    /// A post-merge header does not carry the empty ommers root.
    OmmersHashNotEmpty { found: H256 },
    /// `extra_data` exceeds the protocol limit.
    ExtraDataTooLong { len: usize, max: usize },
    /// Header gas used exceeds its gas limit.
    GasUsedExceedsGasLimit { gas_used: u64, gas_limit: u64 },
    /// Header gas limit exceeds the protocol maximum.
    GasLimitExceedsMaximum { gas_limit: u64, max: u64 },
    /// A trailing header field disagrees with the fork active at the block timestamp.
    ForkFieldMismatch { field: HeaderField, present: bool },
    /// `blob_gas_used` is not an integral number of blobs.
    BlobGasUsedNotMultiple { blob_gas_used: u64 },
    /// `blob_gas_used` exceeds the active schedule's block limit.
    BlobGasUsedExceedsMaximum { blob_gas_used: u64, max: u64 },
    /// The current header does not name the supplied parent.
    ParentHashMismatch { header: H256, parent: H256 },
    /// The current block number does not immediately follow the parent.
    ParentNumberMismatch { parent: u64, child: u64 },
    /// The current timestamp is not greater than the parent's.
    TimestampNotAfterParent { parent: u64, child: u64 },
    /// The block gas limit increased by at least the allowed parent-relative bound.
    GasLimitInvalidIncrease { parent: u64, child: u64 },
    /// The block gas limit decreased by at least the allowed parent-relative bound.
    GasLimitInvalidDecrease { parent: u64, child: u64 },
    /// The block gas limit is below the protocol minimum.
    GasLimitBelowMinimum { gas_limit: u64, min: u64 },
    /// The next EIP-1559 base fee could not be calculated.
    BaseFeeTransitionUnavailable,
    /// The header base fee differs from the parent-derived value.
    BaseFeeMismatch { header: u64, expected: u64 },
    /// The next excess blob gas could not be calculated.
    ExcessBlobGasTransitionUnavailable,
    /// The header excess blob gas differs from the parent-derived value.
    ExcessBlobGasMismatch { header: u64, expected: u64 },
    /// The body-derived transactions root differs from the header.
    TransactionsRootMismatch { header: H256, computed: H256 },
    /// The header and body disagree on whether withdrawals are present.
    WithdrawalsPresenceMismatch { header: bool, body: bool },
    /// The body-derived withdrawals root differs from the header.
    WithdrawalsRootMismatch { header: H256, computed: H256 },
    /// The body's blob count does not match the header's `blob_gas_used`.
    BlobGasUsedMismatch { header: u64, computed: u64 },
    /// Blob-count or RLP-length arithmetic overflowed.
    ArithmeticOverflow,
    /// The canonical block RLP exceeds the EIP-7934 limit.
    BlockTooLarge {
        /// Length lower bound observed when the limit was crossed; exact after a complete scan.
        rlp_length: usize,
        /// Maximum canonical block RLP length.
        max: usize,
    },
}

impl fmt::Display for BlockValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CancunNotActive { timestamp } => {
                write!(f, "Cancun is not active at timestamp {timestamp}")
            }
            Self::DifficultyNotZero { difficulty } => {
                write!(f, "post-merge difficulty is {difficulty}, expected zero")
            }
            Self::NonceNotZero { nonce } => {
                write!(f, "post-merge nonce is {nonce:02x?}, expected zero")
            }
            Self::OmmersHashNotEmpty { found } => {
                write!(f, "post-merge ommers hash is {found:#x}, expected empty")
            }
            Self::ExtraDataTooLong { len, max } => {
                write!(f, "extra data is {len} bytes, exceeding the maximum {max}")
            }
            Self::GasUsedExceedsGasLimit {
                gas_used,
                gas_limit,
            } => {
                write!(f, "gas used {gas_used} exceeds gas limit {gas_limit}")
            }
            Self::GasLimitExceedsMaximum { gas_limit, max } => {
                write!(f, "gas limit {gas_limit} exceeds the maximum {max}")
            }
            Self::ForkFieldMismatch { field, present } => {
                if *present {
                    write!(f, "`{field}` is set before its fork")
                } else {
                    write!(f, "`{field}` is missing after its fork")
                }
            }
            Self::BlobGasUsedNotMultiple { blob_gas_used } => write!(
                f,
                "blob gas used {blob_gas_used} is not a multiple of {DATA_GAS_PER_BLOB}"
            ),
            Self::BlobGasUsedExceedsMaximum { blob_gas_used, max } => {
                write!(f, "blob gas used {blob_gas_used} exceeds the maximum {max}")
            }
            Self::ParentHashMismatch { header, parent } => write!(
                f,
                "header names parent {header:#x}, but the supplied parent hashes to {parent:#x}"
            ),
            Self::ParentNumberMismatch { parent, child } => {
                write!(
                    f,
                    "block {child} does not immediately follow parent {parent}"
                )
            }
            Self::TimestampNotAfterParent { parent, child } => write!(
                f,
                "block timestamp {child} is not greater than parent timestamp {parent}"
            ),
            Self::GasLimitInvalidIncrease { parent, child } => write!(
                f,
                "gas limit increased from {parent} to {child} beyond the allowed bound"
            ),
            Self::GasLimitInvalidDecrease { parent, child } => write!(
                f,
                "gas limit decreased from {parent} to {child} beyond the allowed bound"
            ),
            Self::GasLimitBelowMinimum { gas_limit, min } => {
                write!(f, "gas limit {gas_limit} is below the minimum {min}")
            }
            Self::BaseFeeTransitionUnavailable => {
                f.write_str("the next base fee could not be calculated")
            }
            Self::BaseFeeMismatch { header, expected } => {
                write!(f, "header base fee is {header}, expected {expected}")
            }
            Self::ExcessBlobGasTransitionUnavailable => {
                f.write_str("the next excess blob gas could not be calculated")
            }
            Self::ExcessBlobGasMismatch { header, expected } => {
                write!(f, "header excess blob gas is {header}, expected {expected}")
            }
            Self::TransactionsRootMismatch { header, computed } => write!(
                f,
                "transactions root is {header:#x}, but the body derives {computed:#x}"
            ),
            Self::WithdrawalsPresenceMismatch { header, body } => write!(
                f,
                "withdrawals root present: {header}, withdrawals list present: {body}"
            ),
            Self::WithdrawalsRootMismatch { header, computed } => write!(
                f,
                "withdrawals root is {header:#x}, but the body derives {computed:#x}"
            ),
            Self::BlobGasUsedMismatch { header, computed } => {
                write!(
                    f,
                    "blob gas used is {header}, but the body derives {computed}"
                )
            }
            Self::ArithmeticOverflow => f.write_str("block validation arithmetic overflowed"),
            Self::BlockTooLarge { rlp_length, max } => write!(
                f,
                "block RLP is at least {rlp_length} bytes, exceeding the maximum {max}"
            ),
        }
    }
}

impl core::error::Error for BlockValidationError {}
