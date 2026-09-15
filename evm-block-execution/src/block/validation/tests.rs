//! Tests for header, parent-relative and body validation.

mod bench;
mod corpus;

use super::{
    BlockValidationError, MAX_RLP_BLOCK_SIZE, MAXIMUM_GAS_LIMIT, add_blob_count,
    calculate_blob_gas_used, calculate_block_rlp_length, calculate_body_metrics,
    validate_block_consensus, validate_block_size, validate_shanghai_withdrawals,
};
use crate::block::codec::tests::vectors;
use crate::block::{Block, BlockBody, Header, RecoveredBlock};
use crate::chain_spec::{ChainSpec, HardForkActivationTime};
use crate::constants::{EMPTY_REQUESTS_HASH, EMPTY_ROOT_HASH};
use crate::eips::eip1559::{BaseFeeParams, GAS_LIMIT_BOUND_DIVISOR};
use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::eips::eip7840::BlobParams;
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
const BPO_TIMESTAMP: u64 = 400;
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
        let active_spec = chain_spec
            .active_spec_at_timestamp(timestamp)
            .map(|active| active.spec());
        let parent_spec = chain_spec
            .active_spec_at_timestamp(timestamp - 1)
            .map(|active| active.spec());

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
        .map(|_| ())
    }

    fn relink(&mut self) {
        self.block.header.parent_hash = self.parent.hash_slow();
    }

    fn sync_body_commitments(&mut self) {
        let active_spec = self
            .chain_spec
            .active_spec_at_timestamp(self.block.timestamp)
            .unwrap();
        let metrics =
            calculate_body_metrics(&self.block.header, &self.block.body, active_spec.spec())
                .unwrap();
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

#[test]
fn consensus_validation_returns_the_timestamp_resolved_context() {
    let fixture = Fixture::new(Spec::Osaka, PRAGUE_TIMESTAMP + 1);
    let recovered = RecoveredBlock::try_new_unhashed(fixture.block.clone(), Vec::new()).unwrap();

    let active_spec = validate_block_consensus(
        &fixture.chain_spec,
        &recovered,
        &fixture.parent.clone().seal_slow(),
    )
    .unwrap();
    assert_eq!(
        (active_spec.spec(), active_spec.blob_params()),
        (Spec::Prague, BlobParams::prague())
    );
}

#[test]
fn bpo_activation_changes_the_parent_blob_gas_transition() {
    let mut fixture = Fixture::new(Spec::Osaka, BPO_TIMESTAMP);
    fixture.chain_spec.blob_schedule =
        BlobScheduleBlobParams::mainnet().with_scheduled([(BPO_TIMESTAMP, BlobParams::bpo1())]);

    // Nine blobs are above Osaka's target but below BPO1's. This makes the expected child
    // excess zero under BPO1 and three blobs under the obsolete Osaka parameters.
    let parent_blob_gas = 9 * DATA_GAS_PER_BLOB;
    assert_eq!(
        BlobParams::bpo1().next_block_excess_blob_gas(0, parent_blob_gas, BASE_FEE),
        Some(0)
    );
    assert_eq!(
        BlobParams::osaka().next_block_excess_blob_gas(0, parent_blob_gas, BASE_FEE),
        Some(3 * DATA_GAS_PER_BLOB)
    );
    fixture.parent.blob_gas_used = Some(parent_blob_gas);
    fixture.parent.excess_blob_gas = Some(0);
    fixture.relink();

    let recovered = RecoveredBlock::try_new_unhashed(fixture.block.clone(), Vec::new()).unwrap();
    let active_spec = validate_block_consensus(
        &fixture.chain_spec,
        &recovered,
        &fixture.parent.clone().seal_slow(),
    )
    .unwrap();

    assert_eq!(active_spec.spec(), Spec::Osaka);
    assert_eq!(active_spec.blob_params(), BlobParams::bpo1());

    let osaka_excess = 3 * DATA_GAS_PER_BLOB;
    fixture.block.header.excess_blob_gas = Some(osaka_excess);
    assert_eq!(
        fixture.validate(),
        Err(BlockValidationError::ExcessBlobGasMismatch {
            header: osaka_excess,
            expected: 0,
        })
    );
}

#[test]
fn bpo_block_blob_limit_is_used_by_consensus_validation() {
    let mut fixture = Fixture::new(Spec::Osaka, BPO_TIMESTAMP + 1);
    fixture.chain_spec.blob_schedule =
        BlobScheduleBlobParams::mainnet().with_scheduled([(BPO_TIMESTAMP, BlobParams::bpo1())]);

    // Ten blobs exceed Osaka's block limit but fit under BPO1, so the same block distinguishes
    // whether consensus validation uses the scheduled parameters.
    let blob_count = BlobParams::osaka().max_blob_count + 1;
    assert!(blob_count <= BlobParams::bpo1().max_blob_count);
    let transaction = blob_transaction();
    fixture.block.body.transactions =
        vec![transaction; usize::try_from(blob_count).expect("test blob count fits in usize")];
    fixture.block.header.blob_gas_used = Some(blob_count * DATA_GAS_PER_BLOB);
    fixture.sync_body_commitments();

    assert_eq!(fixture.validate(), Ok(()));

    fixture.chain_spec.blob_schedule = BlobScheduleBlobParams::mainnet();
    assert_eq!(
        fixture.validate(),
        Err(BlockValidationError::BlobGasUsedExceedsMaximum {
            blob_gas_used: blob_count * DATA_GAS_PER_BLOB,
            max: BlobParams::osaka().max_blob_gas_per_block(),
        })
    );
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
    /// The field a mutation violates, whether the header then carries it, and the mutation.
    type Violation = (HeaderField, bool, fn(&mut Header));

    // One row per trailing field, covering the error exposed by the complete validation
    // pipeline. Some required fields are deliberately checked again by later stages.
    let mutations: [Violation; 8] = [
        (HeaderField::BaseFeePerGas, false, |header| {
            header.base_fee_per_gas = None;
        }),
        (HeaderField::WithdrawalsRoot, false, |header| {
            header.withdrawals_root = None;
        }),
        (HeaderField::BlobGasUsed, false, |header| {
            header.blob_gas_used = None;
        }),
        (HeaderField::ParentBeaconBlockRoot, false, |header| {
            header.parent_beacon_block_root = None;
        }),
        (HeaderField::ExcessBlobGas, false, |header| {
            header.excess_blob_gas = None;
        }),
        (HeaderField::RequestsHash, false, |header| {
            header.requests_hash = None;
        }),
        (HeaderField::BlockAccessListHash, true, |header| {
            header.block_access_list_hash = Some(H256::zero());
        }),
        (HeaderField::SlotNumber, true, |header| {
            header.slot_number = Some(0);
        }),
    ];

    for (field, present, mutate) in mutations {
        let mut fixture = Fixture::new(Spec::Osaka, OSAKA_TIMESTAMP + 1);
        mutate(&mut fixture.block.header);
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::ForkFieldMismatch { field, present }),
            "{field:?}"
        );
    }
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
fn block_validation_accepts_parent_derived_base_fee_increases_and_decreases() {
    for (parent_gas_used, expected_base_fee) in [(GAS_LIMIT, 112), (0, 88)] {
        let mut fixture = Fixture::new(Spec::Cancun, CANCUN_TIMESTAMP + 1);
        fixture.parent.gas_used = parent_gas_used;
        fixture.block.header.base_fee_per_gas = Some(expected_base_fee);
        fixture.relink();
        assert_eq!(
            fixture.validate(),
            Ok(()),
            "parent gas used {parent_gas_used}"
        );

        fixture.block.header.base_fee_per_gas = Some(expected_base_fee + 1);
        assert_eq!(
            fixture.validate(),
            Err(BlockValidationError::BaseFeeMismatch {
                header: expected_base_fee + 1,
                expected: expected_base_fee,
            }),
            "parent gas used {parent_gas_used}"
        );
    }
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
fn withdrawals_validation_rejects_joint_absence() {
    assert_eq!(
        validate_shanghai_withdrawals(None, None),
        Err(BlockValidationError::ForkFieldMismatch {
            field: HeaderField::WithdrawalsRoot,
            present: false,
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
fn body_metrics_match_eest_vectors() {
    for vector in vectors() {
        let block = Block::decode_exact(vector.rlp).unwrap();
        let metrics = calculate_body_metrics(&block.header, &block.body, Spec::Osaka).unwrap();
        assert_eq!(metrics.block_rlp_length, vector.rlp.len());
        assert_eq!(metrics.transactions_root, block.header.transactions_root);
        assert_eq!(metrics.withdrawals_root, block.header.withdrawals_root);
    }
}

#[test]
fn oversized_osaka_body_stops_at_the_first_proven_oversized_length() {
    let mut fixture = Fixture::new(Spec::Osaka, OSAKA_TIMESTAMP + 1);
    let mut transaction = blob_transaction();
    match &mut transaction {
        SignedTxEnvelope::Eip4844(signed) => {
            signed.tx.data = vec![0; MAX_RLP_BLOCK_SIZE];
        }
        _ => unreachable!("blob_transaction always returns EIP-4844"),
    }
    fixture.block.body.transactions.push(transaction);
    // Use the block codec as an independent oracle for the checked prefix and complete body.
    let checked_length = rlp::encode(&fixture.block).len();
    fixture.block.body.transactions.push(blob_transaction());
    let full_length = rlp::encode(&fixture.block).len();
    assert!(checked_length > MAX_RLP_BLOCK_SIZE);
    assert!(checked_length < full_length);

    assert_eq!(
        fixture.validate(),
        Err(BlockValidationError::BlockTooLarge {
            rlp_length: checked_length,
            max: MAX_RLP_BLOCK_SIZE,
        })
    );
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

#[test]
fn block_size_check_has_no_overflow_sentinel() {
    // Representability is checked by the length pass; this function only applies EIP-7934.
    assert_eq!(validate_block_size(usize::MAX, Spec::Prague), Ok(()));
    assert_eq!(
        validate_block_size(usize::MAX, Spec::Osaka),
        Err(BlockValidationError::BlockTooLarge {
            rlp_length: usize::MAX,
            max: MAX_RLP_BLOCK_SIZE,
        }),
    );
}

#[test]
fn block_length_overflow_preserves_component_lengths() {
    // Cover the transaction-list prefix, each payload addition, and the outer list prefix.
    for (header_length, transactions_payload_length, withdrawals_length) in [
        (0, usize::MAX, 0),
        (usize::MAX, 0, 0),
        (usize::MAX - 1, 0, 0),
        (0, 0, usize::MAX),
        (usize::MAX - 2, 0, 0),
    ] {
        assert_eq!(
            calculate_block_rlp_length(
                header_length,
                transactions_payload_length,
                withdrawals_length,
            ),
            Err(BlockValidationError::BlockRlpLengthOverflow {
                header_length,
                transactions_payload_length,
                withdrawals_length,
            }),
        );
    }
    let header_length = usize::MAX - size_of::<usize>() - 3;
    assert_eq!(
        calculate_block_rlp_length(header_length, 0, 0),
        Ok(usize::MAX)
    );
    assert!(calculate_block_rlp_length(header_length + 1, 0, 0).is_err());
}

#[test]
fn blob_count_overflow_preserves_transaction_index() {
    assert_eq!(add_blob_count(0, 0, 17), Ok(0));
    assert_eq!(add_blob_count(u64::MAX - 1, 1, 17), Ok(u64::MAX));
    assert_eq!(
        add_blob_count(u64::MAX, 1, 17),
        Err(BlockValidationError::BlobCountOverflow {
            transaction_index: 17,
            accumulated: u64::MAX,
            additional: 1,
        }),
    );
}

#[test]
fn blob_gas_overflow_is_distinct_from_header_mismatch() {
    let max_count = u64::MAX / DATA_GAS_PER_BLOB;
    assert_eq!(calculate_blob_gas_used(0), Ok(0));
    assert_eq!(
        calculate_blob_gas_used(max_count),
        Ok(max_count * DATA_GAS_PER_BLOB)
    );
    assert_eq!(
        calculate_blob_gas_used(max_count + 1),
        Err(BlockValidationError::BlobGasOverflow {
            blob_count: max_count + 1
        }),
    );
}

#[test]
fn transaction_length_error_preserves_source_and_index() {
    use crate::transaction::types::TxLengthError;
    use core::error::Error;

    for source in [
        TxLengthError::AccessList,
        TxLengthError::AuthorizationList,
        TxLengthError::BlobHashes,
        TxLengthError::Payload,
        TxLengthError::Envelope,
    ] {
        let error = BlockValidationError::TransactionLengthOverflow {
            transaction_index: 17,
            source,
        };
        assert_eq!(error.to_string(), format!("transaction 17: {source}"));
        assert_eq!(
            error.source().unwrap().downcast_ref::<TxLengthError>(),
            Some(&source)
        );
    }
    assert!(
        BlockValidationError::BlobGasOverflow {
            blob_count: u64::MAX
        }
        .source()
        .is_none()
    );
}
