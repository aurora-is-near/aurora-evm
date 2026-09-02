//! Parent-relative and pre-execution consensus validation for post-merge blocks.
//!
//! Validation follows pipeline: standalone header rules, rules against the verified
//! parent, then body commitments. This crate supports Cancun-or-later blocks only.
//! The block codec also accepts earlier forks, but this validator intentionally rejects them.

use crate::block::{BlockBody, Header, RecoveredBlock, SealedHeader};
use crate::chain_spec::ChainSpec;
use crate::constants::EMPTY_OMMER_ROOT_HASH;
use crate::eips::eip1559::GAS_LIMIT_BOUND_DIVISOR;
use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::eips::eip7840::BlobParams;
use crate::errors::HeaderField;
use crate::spec::Spec;
use crate::transaction::{SignedTxEnvelope, TxType};
use crate::trie::ordered_trie_root;
use core::fmt;
use primitive_types::{H256, U256};

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
///
/// # Errors
/// [`BlockValidationError`] if the header, parent transition or body commitments are invalid.
pub fn validate_block_consensus(
    chain_spec: &ChainSpec,
    block: &RecoveredBlock,
    parent: &SealedHeader,
) -> Result<(), BlockValidationError> {
    let (active_spec, blob_params) = validate_header(chain_spec, block.header())?;
    validate_header_against_parent(block.sealed_header(), parent, chain_spec, blob_params)?;
    validate_block_pre_execution(block, active_spec)
}

/// Validates rules that need only the current header.
fn validate_header(
    chain_spec: &ChainSpec,
    header: &Header,
) -> Result<(Spec, BlobParams), BlockValidationError> {
    let active_spec = chain_spec
        .active_spec_at_timestamp(header.timestamp)
        .ok_or(BlockValidationError::CancunNotActive {
            timestamp: header.timestamp,
        })?;
    let blob_params = chain_spec
        .blob_params_at_timestamp(header.timestamp)
        .ok_or(BlockValidationError::CancunNotActive {
            timestamp: header.timestamp,
        })?;

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
    if header.extra_data.len() > MAX_EXTRA_DATA_SIZE {
        return Err(BlockValidationError::ExtraDataTooLong {
            len: header.extra_data.len(),
            max: MAX_EXTRA_DATA_SIZE,
        });
    }
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

    validate_fork_fields(header, active_spec)?;
    validate_blob_header(header, blob_params)?;
    Ok((active_spec, blob_params))
}

/// Validates the positional header tail selected by the active fork.
fn validate_fork_fields(header: &Header, active_spec: Spec) -> Result<(), BlockValidationError> {
    validate_fork_field(
        HeaderField::BaseFeePerGas,
        header.base_fee_per_gas.is_some(),
        true,
    )?;
    validate_fork_field(
        HeaderField::WithdrawalsRoot,
        header.withdrawals_root.is_some(),
        true,
    )?;
    validate_fork_field(
        HeaderField::BlobGasUsed,
        header.blob_gas_used.is_some(),
        true,
    )?;
    validate_fork_field(
        HeaderField::ExcessBlobGas,
        header.excess_blob_gas.is_some(),
        true,
    )?;
    validate_fork_field(
        HeaderField::ParentBeaconBlockRoot,
        header.parent_beacon_block_root.is_some(),
        true,
    )?;
    validate_fork_field(
        HeaderField::RequestsHash,
        header.requests_hash.is_some(),
        active_spec >= Spec::Prague,
    )?;
    validate_fork_field(
        HeaderField::BlockAccessListHash,
        header.block_access_list_hash.is_some(),
        false,
    )?;
    validate_fork_field(HeaderField::SlotNumber, header.slot_number.is_some(), false)
}

/// Validates one optional fork field.
const fn validate_fork_field(
    field: HeaderField,
    present: bool,
    required: bool,
) -> Result<(), BlockValidationError> {
    if present == required {
        Ok(())
    } else {
        Err(BlockValidationError::ForkFieldMismatch { field, present })
    }
}

/// Validates EIP-4844 fields that do not depend on the parent or body.
fn validate_blob_header(
    header: &Header,
    blob_params: BlobParams,
) -> Result<(), BlockValidationError> {
    let blob_gas_used = header
        .blob_gas_used
        .ok_or(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::BlobGasUsed,
            present: false,
        })?;
    if !blob_gas_used.is_multiple_of(DATA_GAS_PER_BLOB) {
        return Err(BlockValidationError::BlobGasUsedNotMultiple { blob_gas_used });
    }

    let max = blob_params.max_blob_gas_per_block();
    if blob_gas_used > max {
        return Err(BlockValidationError::BlobGasUsedExceedsMaximum { blob_gas_used, max });
    }
    Ok(())
}

/// Validates the current header against its parent.
fn validate_header_against_parent(
    header: &SealedHeader,
    parent: &SealedHeader,
    chain_spec: &ChainSpec,
    blob_params: BlobParams,
) -> Result<(), BlockValidationError> {
    let parent_hash = parent.hash();
    if header.parent_hash != parent_hash {
        return Err(BlockValidationError::ParentHashMismatch {
            header: header.parent_hash,
            parent: parent_hash,
        });
    }
    if parent.number.checked_add(1) != Some(header.number) {
        return Err(BlockValidationError::ParentNumberMismatch {
            parent: parent.number,
            child: header.number,
        });
    }
    if header.timestamp <= parent.timestamp {
        return Err(BlockValidationError::TimestampNotAfterParent {
            parent: parent.timestamp,
            child: header.timestamp,
        });
    }

    validate_gas_limit_against_parent(header.gas_limit, parent.gas_limit)?;

    let base_fee = header
        .base_fee_per_gas
        .ok_or(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::BaseFeePerGas,
            present: false,
        })?;
    let expected_base_fee = parent
        .next_block_base_fee(chain_spec.base_fee_params)
        .ok_or(BlockValidationError::BaseFeeTransitionUnavailable)?;
    if base_fee != expected_base_fee {
        return Err(BlockValidationError::BaseFeeMismatch {
            header: base_fee,
            expected: expected_base_fee,
        });
    }

    let excess_blob_gas =
        header
            .excess_blob_gas
            .ok_or(BlockValidationError::ForkFieldMismatch {
                field: HeaderField::ExcessBlobGas,
                present: false,
            })?;
    // At the Cancun transition the parent has no blob fields; EIP-4844 defines both as zero.
    let expected_excess_blob_gas = blob_params
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

/// Validates the EIP-1559 gas-limit ramp and minimum.
const fn validate_gas_limit_against_parent(
    gas_limit: u64,
    parent_gas_limit: u64,
) -> Result<(), BlockValidationError> {
    let bound = parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR;
    if gas_limit > parent_gas_limit && gas_limit - parent_gas_limit >= bound {
        return Err(BlockValidationError::GasLimitInvalidIncrease {
            parent: parent_gas_limit,
            child: gas_limit,
        });
    }
    if gas_limit < parent_gas_limit && parent_gas_limit - gas_limit >= bound {
        return Err(BlockValidationError::GasLimitInvalidDecrease {
            parent: parent_gas_limit,
            child: gas_limit,
        });
    }
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

/// Derives body commitments and the canonical block RLP length in one encoding pass.
fn calculate_body_metrics(
    header: &Header,
    body: &BlockBody,
) -> Result<BodyMetrics, BlockValidationError> {
    let mut scratch = rlp::RlpStream::new();
    let mut transactions_payload_length = 0usize;
    let mut blob_count = 0u64;

    let transaction_values = body.transactions.iter().map(|transaction| {
        let envelope = transaction.encode_2718_in(&mut scratch);
        let block_item_length = if transaction.tx_type() == TxType::Legacy {
            envelope.len()
        } else {
            rlp_container_length(envelope.len()).unwrap_or(usize::MAX)
        };
        // Saturation is detected by the checked container-length calculation below. Keeping this
        // iterator streaming avoids a second attacker-sized vector before trie construction.
        transactions_payload_length = transactions_payload_length.saturating_add(block_item_length);

        if let SignedTxEnvelope::Eip4844(transaction) = transaction {
            let count =
                u64::try_from(transaction.tx.blob_versioned_hashes.len()).unwrap_or(u64::MAX);
            blob_count = blob_count.saturating_add(count);
        }
        envelope.to_vec()
    });

    let transactions_root = ordered_trie_root(transaction_values);
    let transactions_length = rlp_container_length(transactions_payload_length)?;

    let (withdrawals_root, withdrawals_length) = match body.withdrawals() {
        Some(withdrawals) => {
            let mut payload_length = 0usize;
            let values = withdrawals.iter().map(|withdrawal| {
                let value = rlp::encode(withdrawal);
                payload_length = payload_length.saturating_add(value.len());
                value
            });
            (
                Some(ordered_trie_root(values)),
                rlp_container_length(payload_length)?,
            )
        }
        None => (None, 0),
    };

    let block_payload_length = rlp::encode(header)
        .len()
        .checked_add(transactions_length)
        // The body model has no ommers, so its encoded list is the one-byte empty list.
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(withdrawals_length))
        .ok_or(BlockValidationError::ArithmeticOverflow)?;
    let block_rlp_length = rlp_container_length(block_payload_length)?;
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

/// Returns the encoded length of an RLP list or non-single-byte string with this payload length.
fn rlp_container_length(payload_length: usize) -> Result<usize, BlockValidationError> {
    let prefix_length = if payload_length <= 55 {
        1
    } else {
        1usize
            .checked_add(encoded_usize_length(payload_length))
            .ok_or(BlockValidationError::ArithmeticOverflow)?
    };
    prefix_length
        .checked_add(payload_length)
        .ok_or(BlockValidationError::ArithmeticOverflow)
}

/// Number of bytes in the minimal big-endian representation of a non-zero `usize`.
fn encoded_usize_length(value: usize) -> usize {
    usize::try_from((usize::BITS - value.leading_zeros()).div_ceil(8)).unwrap_or(usize::MAX)
}

/// Validates commitments and body-only fork rules.
fn validate_block_pre_execution(
    block: &RecoveredBlock,
    active_spec: Spec,
) -> Result<(), BlockValidationError> {
    let header = block.header();
    let metrics = calculate_body_metrics(header, block.body())?;

    validate_block_size(metrics.block_rlp_length, active_spec)?;

    if metrics.transactions_root != header.transactions_root {
        return Err(BlockValidationError::TransactionsRootMismatch {
            header: header.transactions_root,
            computed: metrics.transactions_root,
        });
    }
    match (header.withdrawals_root, metrics.withdrawals_root) {
        (Some(header), Some(computed)) if header != computed => {
            return Err(BlockValidationError::WithdrawalsRootMismatch { header, computed });
        }
        (Some(_), Some(_)) | (None, None) => {}
        (header, body) => {
            return Err(BlockValidationError::WithdrawalsPresenceMismatch {
                header: header.is_some(),
                body: body.is_some(),
            });
        }
    }

    let header_blob_gas_used =
        header
            .blob_gas_used
            .ok_or(BlockValidationError::ForkFieldMismatch {
                field: HeaderField::BlobGasUsed,
                present: false,
            })?;
    if metrics.blob_gas_used != header_blob_gas_used {
        return Err(BlockValidationError::BlobGasUsedMismatch {
            header: header_blob_gas_used,
            computed: metrics.blob_gas_used,
        });
    }
    Ok(())
}

/// Applies EIP-7934 from Osaka onward.
fn validate_block_size(rlp_length: usize, active_spec: Spec) -> Result<(), BlockValidationError> {
    if active_spec >= Spec::Osaka && rlp_length > MAX_RLP_BLOCK_SIZE {
        Err(BlockValidationError::BlockTooLarge {
            rlp_length,
            max: MAX_RLP_BLOCK_SIZE,
        })
    } else {
        Ok(())
    }
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
    BlockTooLarge { rlp_length: usize, max: usize },
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
                "block RLP is {rlp_length} bytes, exceeding the maximum {max}"
            ),
        }
    }
}

impl core::error::Error for BlockValidationError {}

#[cfg(test)]
mod tests {
    use super::{
        BlockValidationError, MAX_RLP_BLOCK_SIZE, MAXIMUM_GAS_LIMIT, calculate_body_metrics,
        validate_block_consensus, validate_block_size,
    };
    use crate::block::codec::tests::vectors;
    use crate::block::{Block, BlockBody, Header, RecoveredBlock};
    use crate::chain_spec::{ChainSpec, HardForkActivationTime};
    use crate::constants::{EMPTY_REQUESTS_HASH, EMPTY_ROOT_HASH};
    use crate::eips::eip1559::{BaseFeeParams, GAS_LIMIT_BOUND_DIVISOR};
    use crate::eips::eip4844::DATA_GAS_PER_BLOB;
    use crate::eips::eip7892::BlobScheduleBlobParams;
    use crate::errors::HeaderField;
    use crate::spec::Spec;
    use crate::transaction::SignedTxEnvelope;
    use crate::withdrawal::Withdrawal;
    use hex_literal::hex;
    use primitive_types::{H160, H256, U256};

    const CANCUN_TIMESTAMP: u64 = 100;
    const PRAGUE_TIMESTAMP: u64 = 200;
    const OSAKA_TIMESTAMP: u64 = 300;
    const GAS_LIMIT: u64 = 30_000_000;
    const BASE_FEE: u64 = 100;

    fn chain_spec(spec: Spec) -> ChainSpec {
        ChainSpec {
            chain_id: 1,
            spec,
            hard_forks_timestamps: HardForkActivationTime::from([
                (Spec::Cancun, CANCUN_TIMESTAMP),
                (Spec::Prague, PRAGUE_TIMESTAMP),
                (Spec::Osaka, OSAKA_TIMESTAMP),
            ]),
            deposit_contract_address: None,
            base_fee_params: BaseFeeParams::ethereum(),
            blob_schedule: BlobScheduleBlobParams::mainnet(),
        }
    }

    fn active_header(spec: Option<Spec>, timestamp: u64) -> Header {
        Header {
            gas_limit: GAS_LIMIT,
            gas_used: GAS_LIMIT / 2,
            timestamp,
            base_fee_per_gas: Some(BASE_FEE),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: spec.is_some().then_some(0),
            excess_blob_gas: spec.is_some().then_some(0),
            parent_beacon_block_root: spec.map(|_| H256::zero()),
            requests_hash: spec
                .is_some_and(|spec| spec >= Spec::Prague)
                .then_some(EMPTY_REQUESTS_HASH),
            ..Header::default()
        }
    }

    struct Fixture {
        chain_spec: ChainSpec,
        parent: Header,
        block: Block,
    }

    impl Fixture {
        fn new(max_spec: Spec, timestamp: u64) -> Self {
            let chain_spec = chain_spec(max_spec);
            let active_spec = chain_spec.active_spec_at_timestamp(timestamp);
            let parent_spec = chain_spec.active_spec_at_timestamp(timestamp - 1);

            let mut parent = active_header(parent_spec, timestamp - 1);
            parent.number = 10;
            parent.state_root = H256::repeat_byte(0x11);

            let mut header = active_header(active_spec, timestamp);
            header.number = 11;
            header.parent_hash = parent.hash_slow();
            header.gas_used = 0;
            let body = BlockBody::new(Vec::new(), Some(Vec::new()));
            let block = Block::new(header, body);

            Self {
                chain_spec,
                parent,
                block,
            }
        }

        fn validate(&self) -> Result<(), BlockValidationError> {
            let senders = vec![H160::zero(); self.block.transactions().len()];
            let recovered = RecoveredBlock::try_new_unhashed(self.block.clone(), senders).unwrap();
            validate_block_consensus(
                &self.chain_spec,
                &recovered,
                &self.parent.clone().seal_slow(),
            )
        }

        fn relink(&mut self) {
            self.block.header.parent_hash = self.parent.hash_slow();
        }

        fn sync_body_commitments(&mut self) {
            let metrics = calculate_body_metrics(&self.block.header, &self.block.body).unwrap();
            self.block.header.transactions_root = metrics.transactions_root;
            self.block.header.withdrawals_root = metrics.withdrawals_root;
        }
    }

    /// A real EIP-4844 transaction from the execution-spec fixtures.
    fn blob_transaction() -> SignedTxEnvelope {
        SignedTxEnvelope::decode_2718(&hex!(
            "03f8a601808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a00000"
            "00000000000000000000000000000000000000000000000000000000000cc001e1a00100"
            "00000000000000000000000000000000000000000000000000000000000001a08cdee4f5"
            "29448c31aef67fb75346f7e0279e9545da3194191835349e19888b41a013e7d078013af8"
            "d334a2b09246dad964099443bb85b20d40bb3b08ea3c93229f"
        ))
        .unwrap()
    }

    #[test]
    fn valid_cancun_prague_and_osaka_blocks_pass() {
        for (spec, timestamp) in [
            (Spec::Cancun, CANCUN_TIMESTAMP + 1),
            (Spec::Prague, PRAGUE_TIMESTAMP + 1),
            (Spec::Osaka, OSAKA_TIMESTAMP + 1),
        ] {
            assert_eq!(Fixture::new(spec, timestamp).validate(), Ok(()), "{spec:?}");
        }
    }

    /// A configured upper fork must not bypass Cancun's activation timestamp.
    #[test]
    fn pre_cancun_timestamps_are_rejected() {
        for spec in [Spec::Cancun, Spec::Prague, Spec::Osaka] {
            let fixture = Fixture::new(spec, CANCUN_TIMESTAMP - 1);
            assert_eq!(
                fixture.validate(),
                Err(BlockValidationError::CancunNotActive {
                    timestamp: CANCUN_TIMESTAMP - 1,
                }),
                "{spec:?}"
            );
        }
    }

    #[test]
    fn first_cancun_block_accepts_a_parent_without_blob_fields() {
        let fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP);
        assert_eq!(fixture.parent.blob_gas_used, None);
        assert_eq!(fixture.parent.excess_blob_gas, None);
        assert_eq!(fixture.validate(), Ok(()));
    }

    #[test]
    fn timestamp_selects_fork_fields_within_the_configured_boundary() {
        let mut cancun = Fixture::new(Spec::Osaka, PRAGUE_TIMESTAMP - 1);
        assert_eq!(cancun.block.header.requests_hash, None);
        assert_eq!(cancun.validate(), Ok(()));

        cancun.block.header.requests_hash = Some(EMPTY_REQUESTS_HASH);
        assert_eq!(
            cancun.validate(),
            Err(BlockValidationError::ForkFieldMismatch {
                field: HeaderField::RequestsHash,
                present: true,
            })
        );

        let mut prague = Fixture::new(Spec::Osaka, PRAGUE_TIMESTAMP);
        prague.block.header.requests_hash = None;
        assert_eq!(
            prague.validate(),
            Err(BlockValidationError::ForkFieldMismatch {
                field: HeaderField::RequestsHash,
                present: false,
            })
        );
    }

    #[test]
    fn required_and_future_header_fields_are_rejected() {
        let mut fixture = Fixture::new(Spec::Osaka, OSAKA_TIMESTAMP + 1);
        fixture.block.header.parent_beacon_block_root = None;
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::ForkFieldMismatch {
                field: HeaderField::ParentBeaconBlockRoot,
                present: false,
            })
        );

        let mut fixture = Fixture::new(Spec::Osaka, OSAKA_TIMESTAMP + 1);
        fixture.block.header.block_access_list_hash = Some(H256::zero());
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::ForkFieldMismatch {
                field: HeaderField::BlockAccessListHash,
                present: true,
            })
        );
    }

    #[test]
    fn post_merge_fixed_fields_are_enforced() {
        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.difficulty = U256::one();
        assert!(matches!(
            fixture.validate(),
            Err(BlockValidationError::DifficultyNotZero { .. })
        ));

        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.nonce[7] = 1;
        assert!(matches!(
            fixture.validate(),
            Err(BlockValidationError::NonceNotZero { .. })
        ));

        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.ommers_hash = H256::repeat_byte(0x77);
        assert!(matches!(
            fixture.validate(),
            Err(BlockValidationError::OmmersHashNotEmpty { .. })
        ));
    }

    #[test]
    fn header_size_and_gas_bounds_are_enforced() {
        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.extra_data = vec![0; 33];
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::ExtraDataTooLong { len: 33, max: 32 })
        );

        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.gas_used = GAS_LIMIT + 1;
        assert!(matches!(
            fixture.validate(),
            Err(BlockValidationError::GasUsedExceedsGasLimit { .. })
        ));

        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.gas_limit = MAXIMUM_GAS_LIMIT + 1;
        assert!(matches!(
            fixture.validate(),
            Err(BlockValidationError::GasLimitExceedsMaximum { .. })
        ));
    }

    #[test]
    fn blob_gas_must_be_integral_and_within_the_active_limit() {
        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.blob_gas_used = Some(1);
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::BlobGasUsedNotMultiple { blob_gas_used: 1 })
        );

        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        let max = fixture
            .chain_spec
            .blob_params_at_timestamp(fixture.block.timestamp)
            .unwrap()
            .max_blob_gas_per_block();
        fixture.block.header.blob_gas_used = Some(max + DATA_GAS_PER_BLOB);
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::BlobGasUsedExceedsMaximum {
                blob_gas_used: max + DATA_GAS_PER_BLOB,
                max,
            })
        );
    }

    #[test]
    fn parent_hash_number_and_timestamp_are_enforced() {
        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.parent_hash = H256::repeat_byte(0x88);
        assert!(matches!(
            fixture.validate(),
            Err(BlockValidationError::ParentHashMismatch { .. })
        ));

        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.number += 1;
        assert!(matches!(
            fixture.validate(),
            Err(BlockValidationError::ParentNumberMismatch { .. })
        ));

        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.header.timestamp = fixture.parent.timestamp;
        assert!(matches!(
            fixture.validate(),
            Err(BlockValidationError::TimestampNotAfterParent { .. })
        ));
    }

    #[test]
    fn gas_limit_parent_bound_is_exclusive() {
        let bound = GAS_LIMIT / GAS_LIMIT_BOUND_DIVISOR;

        let mut allowed = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        allowed.block.header.gas_limit = GAS_LIMIT + bound - 1;
        assert_eq!(allowed.validate(), Ok(()));

        let mut increase = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        increase.block.header.gas_limit = GAS_LIMIT + bound;
        assert!(matches!(
            increase.validate(),
            Err(BlockValidationError::GasLimitInvalidIncrease { .. })
        ));

        let mut decrease = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        decrease.block.header.gas_limit = GAS_LIMIT - bound;
        assert!(matches!(
            decrease.validate(),
            Err(BlockValidationError::GasLimitInvalidDecrease { .. })
        ));
    }

    #[test]
    fn minimum_gas_limit_is_enforced() {
        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.parent.gas_limit = 5_000;
        fixture.parent.gas_used = 2_500;
        fixture.block.header.gas_limit = 4_999;
        fixture.relink();
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::GasLimitBelowMinimum {
                gas_limit: 4_999,
                min: 5_000,
            })
        );
    }

    #[test]
    fn base_fee_and_excess_blob_gas_are_derived_from_the_parent() {
        let mut base_fee = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        base_fee.block.header.base_fee_per_gas = Some(BASE_FEE + 1);
        assert_eq!(
            base_fee.validate(),
            Err(BlockValidationError::BaseFeeMismatch {
                header: BASE_FEE + 1,
                expected: BASE_FEE,
            })
        );

        let mut excess = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        excess.block.header.excess_blob_gas = Some(1);
        assert_eq!(
            excess.validate(),
            Err(BlockValidationError::ExcessBlobGasMismatch {
                header: 1,
                expected: 0,
            })
        );
    }

    #[test]
    fn body_commitments_are_rederived() {
        let mut transactions = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        transactions.block.header.transactions_root = H256::repeat_byte(0x33);
        assert!(matches!(
            transactions.validate(),
            Err(BlockValidationError::TransactionsRootMismatch { .. })
        ));

        let mut withdrawals = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        withdrawals.block.body.withdrawals = Some(vec![Withdrawal {
            index: 1,
            validator_index: 2,
            address: H160::repeat_byte(0xaa),
            amount: 3,
        }]);
        assert!(matches!(
            withdrawals.validate(),
            Err(BlockValidationError::WithdrawalsRootMismatch { .. })
        ));

        let mut presence = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        presence.block.body.withdrawals = None;
        assert_eq!(
            presence.validate(),
            Err(BlockValidationError::WithdrawalsPresenceMismatch {
                header: true,
                body: false,
            })
        );
    }

    #[test]
    fn body_blob_count_must_match_the_header() {
        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.block.body.transactions.push(blob_transaction());
        fixture.sync_body_commitments();
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::BlobGasUsedMismatch {
                header: 0,
                computed: DATA_GAS_PER_BLOB,
            })
        );
    }

    #[test]
    fn calculated_block_length_matches_eest_vectors() {
        for vector in vectors() {
            let block = Block::decode_exact(vector.rlp).unwrap();
            let metrics = calculate_body_metrics(&block.header, &block.body).unwrap();
            assert_eq!(metrics.block_rlp_length, vector.rlp.len());
        }
    }

    #[test]
    fn eip7934_limit_is_inclusive_and_osaka_only() {
        assert_eq!(validate_block_size(MAX_RLP_BLOCK_SIZE, Spec::Osaka), Ok(()));
        assert_eq!(
            validate_block_size(MAX_RLP_BLOCK_SIZE + 1, Spec::Osaka),
            Err(BlockValidationError::BlockTooLarge {
                rlp_length: MAX_RLP_BLOCK_SIZE + 1,
                max: MAX_RLP_BLOCK_SIZE,
            })
        );
        assert_eq!(
            validate_block_size(MAX_RLP_BLOCK_SIZE + 1, Spec::Prague),
            Ok(())
        );
    }
}
