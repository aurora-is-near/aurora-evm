//! Opt-in differential over the EEST blockchain fixtures.
//!
//! Every fixture starts from its `pre` allocation. Each block is decoded, recovered, validated
//! against its verified ancestors, executed, and its header commitments recomputed from the
//! execution output; `expectException` must fail at a stage allowed by that exception. The final
//! state is compared with `postState`. Only Cancun-or-later networks are executable here.
//!
//! Complete-state mode checks commitments independently. Witness modes use production validation
//! and compare its accepted root with a full-state oracle. Withholding permits only the removed
//! node to be missing; mutations require the exact rejection of each changed header commitment.

use crate::block::{Block, BlockEnv, ExecutionParts, Header, derive_ancestors, recover_block};
use crate::bloom::Bloom;
use crate::chain_spec::ChainSpec;
use crate::crypto::keccak256;
use crate::eips::eip1559::BaseFeeParams;
use crate::eips::eip7840::BlobParams;
use crate::eips::eip7892::BlobScheduleBlobParams;
use crate::errors::BlockExecutionError;
use crate::execution_types::execution::BlockExecutionResult;
use crate::executor::BlockExecutor;
use crate::spec::Spec;
use crate::stateless::{StatelessValidationError, stateless_validation_recovered};
use crate::test_utils::witness_of;
use crate::trie::{receipts_root, state_root};
use crate::witness_backend::WitnessStateError;
use crate::witness_backend::{RevealedAccount, WitnessBackend, WitnessDbError, WitnessState};
use aurora_evm::backend::MemoryAccount;
use core::fmt;
use primitive_types::{H160, H256, U256};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod mutations;
use mutations::check_header_mutations;

fn collect_files(directory: &Path, paths: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, paths);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap().trim_start_matches("0x");
    if text.is_empty() {
        return Vec::new();
    }
    hex::decode(text).unwrap()
}

fn hex_u256(value: &Value) -> U256 {
    let text = value.as_str().unwrap().trim_start_matches("0x");
    if text.is_empty() {
        return U256::zero();
    }
    U256::from_str_radix(text, 16).unwrap()
}

fn hex_h160(text: &str) -> H160 {
    H160::from_slice(&hex::decode(text.trim_start_matches("0x")).unwrap())
}

fn hex_h256(value: &Value) -> H256 {
    H256(hex_u256(value).to_big_endian())
}

fn account_from_json(account: &Value) -> MemoryAccount {
    MemoryAccount {
        nonce: hex_u256(&account["nonce"]),
        balance: hex_u256(&account["balance"]),
        storage: account["storage"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(slot, value)| {
                (
                    H256(
                        U256::from_str_radix(slot.trim_start_matches("0x"), 16)
                            .unwrap()
                            .to_big_endian(),
                    ),
                    hex_h256(value),
                )
            })
            .filter(|(_, value)| !value.is_zero())
            .collect(),
        code: hex_bytes(&account["code"]),
    }
}

fn state_from_json(alloc: &Value) -> BTreeMap<H160, MemoryAccount> {
    alloc
        .as_object()
        .unwrap()
        .iter()
        .map(|(address, account)| (hex_h160(address), account_from_json(account)))
        .collect()
}

/// Timestamp at which the `*AtTime15k` transition networks switch forks.
const TRANSITION_TIMESTAMP: u64 = 15_000;

/// A fixture network: its fork boundary, the fork activation timestamps, and the BPO forks
/// scheduled on top of Osaka by activation timestamp.
type Network = (Spec, Vec<(Spec, u64)>, Vec<(u64, &'static str)>);

/// The chain configuration of a fixture network, `None` for networks this crate cannot execute.
///
/// BPO forks are scheduled blob-parameter updates on top of Osaka. The fixture's
/// `config.blobSchedule` must agree with every fork the crate has constants for; the test-only
/// BPO3 and BPO4 take their values from the fixture.
fn chain_spec(network: &str, chain_id: u64, blob_schedule: &Value) -> Option<ChainSpec> {
    let osaka_at = |timestamp| {
        vec![
            (Spec::Cancun, 0),
            (Spec::Prague, 0),
            (Spec::Osaka, timestamp),
        ]
    };
    let (spec, timestamps, bpos): Network = match network {
        "Cancun" => (Spec::Cancun, vec![(Spec::Cancun, 0)], Vec::new()),
        "Prague" => (
            Spec::Prague,
            vec![(Spec::Cancun, 0), (Spec::Prague, 0)],
            Vec::new(),
        ),
        "CancunToPragueAtTime15k" => (
            Spec::Prague,
            vec![(Spec::Cancun, 0), (Spec::Prague, TRANSITION_TIMESTAMP)],
            Vec::new(),
        ),
        "Osaka" => (Spec::Osaka, osaka_at(0), Vec::new()),
        "PragueToOsakaAtTime15k" => (Spec::Osaka, osaka_at(TRANSITION_TIMESTAMP), Vec::new()),
        "OsakaToBPO1AtTime15k" => (
            Spec::Osaka,
            osaka_at(0),
            vec![(TRANSITION_TIMESTAMP, "BPO1")],
        ),
        "BPO1ToBPO2AtTime15k" => (
            Spec::Osaka,
            osaka_at(0),
            vec![(0, "BPO1"), (TRANSITION_TIMESTAMP, "BPO2")],
        ),
        "BPO2ToBPO3AtTime15k" => (
            Spec::Osaka,
            osaka_at(0),
            vec![(0, "BPO2"), (TRANSITION_TIMESTAMP, "BPO3")],
        ),
        "BPO3ToBPO4AtTime15k" => (
            Spec::Osaka,
            osaka_at(0),
            vec![(0, "BPO3"), (TRANSITION_TIMESTAMP, "BPO4")],
        ),
        _ => return None,
    };
    let mainnet = BlobScheduleBlobParams::mainnet();
    for (fork, constants) in [
        ("Cancun", mainnet.cancun),
        ("Prague", mainnet.prague),
        ("Osaka", mainnet.osaka),
        ("BPO1", BlobParams::bpo1()),
        ("BPO2", BlobParams::bpo2()),
    ] {
        if !blob_schedule[fork].is_null() {
            assert_eq!(
                fixture_blob_params(blob_schedule, fork, constants),
                constants,
                "{network}: the {fork} blob schedule differs from the crate constants"
            );
        }
    }
    let scheduled: Vec<_> = bpos
        .into_iter()
        .map(|(timestamp, fork)| {
            (
                timestamp,
                fixture_blob_params(blob_schedule, fork, BlobParams::osaka()),
            )
        })
        .collect();
    Some(ChainSpec {
        chain_id,
        spec,
        hard_forks_timestamps: timestamps.into_iter().collect(),
        deposit_contract_address: None,
        base_fee_params: BaseFeeParams::ethereum(),
        blob_schedule: mainnet.with_scheduled(scheduled),
    })
}

/// The `fork` entry of a fixture's `config.blobSchedule` applied over `defaults`.
fn fixture_blob_params(blob_schedule: &Value, fork: &str, defaults: BlobParams) -> BlobParams {
    let entry = &blob_schedule[fork];
    assert!(entry.is_object(), "blobSchedule has no {fork} entry");
    let field = |name| u64::try_from(hex_u256(&entry[name])).unwrap();
    BlobParams {
        target_blob_count: field("target"),
        max_blob_count: field("max"),
        update_fraction: field("baseFeeUpdateFraction"),
        ..defaults
    }
}

/// Folds the accounts execution touched into the full state.
///
/// A present account replaces its entry; its slot map holds only the slots execution revealed or
/// wrote, so it is applied on top of the account's previous storage (or an empty one after a wipe)
/// with zeros as removals — the same diff the sparse-trie root will consume. A proven-absent
/// account is removed. A complete-state result carries every account with its whole storage, so
/// folding it into an empty map yields the whole post-state.
fn fold_post_state(
    mut full: BTreeMap<H160, MemoryAccount>,
    state: WitnessState,
) -> BTreeMap<H160, MemoryAccount> {
    let WitnessState {
        accounts, codes, ..
    } = state;
    for (address, revealed) in accounts {
        match revealed {
            RevealedAccount::Present(account) => {
                let code = if account.has_code() {
                    codes[&account.code_hash].clone()
                } else {
                    Vec::new()
                };
                let mut storage = if account.storage_wiped {
                    BTreeMap::new()
                } else {
                    full.get(&address)
                        .map(|previous| previous.storage.clone())
                        .unwrap_or_default()
                };
                for (slot, value) in account.storage {
                    if value.is_zero() {
                        storage.remove(&slot);
                    } else {
                        storage.insert(slot, value);
                    }
                }
                full.insert(
                    address,
                    MemoryAccount {
                        nonce: account.nonce,
                        balance: account.balance,
                        storage,
                        code,
                    },
                );
            }
            RevealedAccount::Absent => {
                full.remove(&address);
            }
        }
    }
    full
}

/// How a fixture block is executed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The executor over the complete state.
    CompleteState,
    /// The production stateless path over a witness derived from the complete state.
    Witness,
    /// Witness mode with one hashed node withheld per block: the block must either be rejected as
    /// unprovable or reach exactly the commitments its header carries — never a third outcome.
    WitnessWithholding,
    /// Valid witness blocks are also retried with each post-execution commitment corrupted.
    WitnessMutations,
}

/// Keeps stateless errors typed until the fixture result has been classified.
enum BlockFailure {
    Stateless(Box<StatelessValidationError>),
    Execution(Box<BlockExecutionError>),
    Commitment(Commitment),
    Other(String),
    /// The differential oracle or a controlled mutation observed an impossible outcome.
    Oracle(String),
}

/// Header fields recomputed by the harness after production execution has succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Commitment {
    GasUsed,
    BlobGasUsed,
    ReceiptsRoot,
    LogsBloom,
    RequestsHash,
    StateRoot,
}

/// Separates invalid blocks from unavailable evidence and internal execution failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureStage {
    PreExecution,
    Execution,
    Commitment,
    Witness,
    Internal,
}

impl BlockFailure {
    fn stage(&self) -> FailureStage {
        match self {
            Self::Stateless(error) => match error.as_ref() {
                StatelessValidationError::Execution(error) => execution_failure_stage(error),
                StatelessValidationError::Witness(_) => FailureStage::Witness,
                StatelessValidationError::PostExecution(_) => FailureStage::Commitment,
                StatelessValidationError::StateRoot(_) => FailureStage::Internal,
                _ => FailureStage::PreExecution,
            },
            Self::Execution(error) => execution_failure_stage(error),
            Self::Commitment(_) => FailureStage::Commitment,
            Self::Other(_) => FailureStage::PreExecution,
            Self::Oracle(_) => FailureStage::Internal,
        }
    }

    /// Transaction exceptions require execution; block exceptions select their permitted stage.
    fn matches_exception(&self, exception: &str) -> bool {
        exception.split('|').any(|exception| {
            let stage = self.stage();
            match exception {
                "BlockException.INVALID_DEPOSIT_EVENT_LAYOUT"
                | "BlockException.SYSTEM_CONTRACT_CALL_FAILED"
                | "BlockException.SYSTEM_CONTRACT_EMPTY" => stage == FailureStage::Execution,
                "BlockException.INVALID_REQUESTS" => {
                    matches!(self, Self::Commitment(Commitment::RequestsHash))
                        || matches!(self, Self::Stateless(error) if matches!(error.as_ref(),
                            StatelessValidationError::PostExecution(BlockExecutionError::RequestsHashMismatch { .. })
                        ))
                }
                "BlockException.RLP_STRUCTURES_ENCODING"
                | "BlockException.BLOB_GAS_USED_ABOVE_LIMIT"
                | "BlockException.INCORRECT_BLOB_GAS_USED"
                | "BlockException.INCORRECT_EXCESS_BLOB_GAS"
                | "BlockException.INVALID_BASEFEE_PER_GAS"
                | "BlockException.INVALID_GASLIMIT"
                | "BlockException.INVALID_WITHDRAWALS_ROOT"
                | "BlockException.INVALID_BLOCK_HASH"
                | "BlockException.RLP_BLOCK_LIMIT_EXCEEDED" => stage == FailureStage::PreExecution,
                // Fixed-width destinations are checked by the codec; block blob limits also
                // have a header-level check before transaction execution. The codec rejects an
                // out-of-range `v` or `y_parity`, and sender recovery a non-normalized `s`
                // (EIP-2) or an `r` without a curve point, before any transaction executes.
                "TransactionException.TYPE_3_TX_CONTRACT_CREATION"
                | "TransactionException.TYPE_4_TX_CONTRACT_CREATION"
                | "TransactionException.TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED"
                | "TransactionException.TYPE_3_TX_BLOB_COUNT_EXCEEDED"
                | "TransactionException.INVALID_SIGNATURE_VRS" => {
                    matches!(stage, FailureStage::PreExecution | FailureStage::Execution)
                }
                exception if exception.starts_with("TransactionException.") => {
                    stage == FailureStage::Execution
                }
                _ => false,
            }
        })
    }

    fn is_unproven(&self) -> bool {
        matches!(self, Self::Stateless(error) if matches!(error.as_ref(),
            StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
                WitnessDbError::Account { .. }
                | WitnessDbError::Code { .. }
                | WitnessDbError::StorageSlot { .. }
                | WitnessDbError::AncestorHash { .. }
                | WitnessDbError::BlindedNode { .. }
            ))
                | StatelessValidationError::Witness(WitnessStateError::PreStateRootNotRevealed { .. })
        ))
    }
}

fn execution_failure_stage(error: &BlockExecutionError) -> FailureStage {
    match error {
        BlockExecutionError::Transaction { source, .. } => execution_failure_stage(source),
        BlockExecutionError::MissingWitness(_) => FailureStage::Witness,
        BlockExecutionError::ExecutionFailed(_) => FailureStage::Internal,
        _ => FailureStage::Execution,
    }
}

impl From<String> for BlockFailure {
    fn from(error: String) -> Self {
        Self::Other(error)
    }
}

impl fmt::Display for BlockFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stateless(error) => write!(
                f,
                "stateless: {error} ({:?})",
                core::error::Error::source(error.as_ref())
            ),
            Self::Other(error) | Self::Oracle(error) => f.write_str(error),
            Self::Execution(error) => write!(f, "execution: {error:?}"),
            Self::Commitment(field) => write!(f, "post-execution mismatch: {field:?}"),
        }
    }
}

#[test]
fn witness_rejections_are_classified_by_type_not_message() {
    let missing = BlockFailure::Stateless(Box::new(StatelessValidationError::Execution(
        BlockExecutionError::MissingWitness(WitnessDbError::Account {
            address: H160::zero(),
        }),
    )));
    let root = BlockFailure::Stateless(Box::new(StatelessValidationError::Witness(
        WitnessStateError::PreStateRootNotRevealed {
            pre_state_root: H256::zero(),
        },
    )));
    let invalid = BlockFailure::Stateless(Box::new(StatelessValidationError::Execution(
        BlockExecutionError::SenderHasCode,
    )));
    let malformed = BlockFailure::Stateless(Box::new(StatelessValidationError::Witness(
        WitnessStateError::StorageContradictsRoot {
            address: H160::zero(),
            slot: H256::zero(),
        },
    )));
    assert!(missing.is_unproven());
    assert!(root.is_unproven());
    assert!(!invalid.is_unproven());
    assert!(!malformed.is_unproven());
    assert!(!BlockFailure::Other("MissingWitness PreStateRootNotRevealed".into()).is_unproven());
    for error in [
        WitnessDbError::MalformedNode { hash: H256::zero() },
        WitnessDbError::AccountLeaf {
            address: H160::zero(),
        },
        WitnessDbError::StorageLeaf {
            address: H160::zero(),
            slot: H256::zero(),
        },
    ] {
        let failure = BlockFailure::Stateless(Box::new(StatelessValidationError::Execution(
            BlockExecutionError::MissingWitness(error),
        )));
        assert!(!failure.is_unproven());
    }
}

#[test]
fn post_execution_and_root_failures_keep_their_distinct_stages() {
    use crate::trie::StateRootError;
    use aurora_evm_trie::sparse::{LookupError, PatchError};

    let requests = BlockFailure::Stateless(Box::new(StatelessValidationError::PostExecution(
        BlockExecutionError::RequestsHashMismatch {
            got: Some(H256::zero()),
            expected: None,
        },
    )));
    assert_eq!(requests.stage(), FailureStage::Commitment);
    assert!(requests.matches_exception("BlockException.INVALID_REQUESTS"));
    assert!(!requests.matches_exception("TransactionException.NONCE_IS_MAX"));
    assert!(!requests.is_unproven());

    let root = BlockFailure::Stateless(Box::new(StatelessValidationError::PostExecution(
        BlockExecutionError::StateRootMismatch {
            got: H256::zero(),
            expected: H256::repeat_byte(1),
        },
    )));
    assert_eq!(root.stage(), FailureStage::Commitment);
    assert!(!root.matches_exception("BlockException.INVALID_REQUESTS"));
    assert!(!root.is_unproven());

    for error in [
        StateRootError::NoTrie,
        StateRootError::MissingAccount(H160::zero()),
        StateRootError::MissingStorageSlot {
            address: H160::zero(),
            slot: H256::zero(),
        },
        StateRootError::Patch(PatchError::EmptyValue),
    ] {
        let failure = BlockFailure::Stateless(Box::new(error.into()));
        assert_eq!(failure.stage(), FailureStage::Internal);
        assert!(!failure.is_unproven());
        assert!(!failure.matches_exception("TransactionException.NONCE_IS_MAX"));
    }

    for (node, unproven) in [
        (LookupError::BlindedNode([1; 32]), true),
        (LookupError::MalformedNode([2; 32]), false),
    ] {
        let failure = BlockFailure::Stateless(Box::new(
            StateRootError::Patch(PatchError::Node(node)).into(),
        ));
        assert_eq!(failure.stage(), FailureStage::Witness);
        assert_eq!(failure.is_unproven(), unproven);
    }
}

#[test]
fn negative_execution_cases_cannot_pass_via_a_commitment_or_witness_failure() {
    let nonce = BlockExecutionError::at_transaction(
        0,
        BlockExecutionError::InvalidNonce {
            tx: U256::from(u64::MAX),
            state: U256::from(u64::MAX),
        },
    );
    for error in [
        BlockFailure::Execution(Box::new(nonce.clone())),
        BlockFailure::Stateless(Box::new(StatelessValidationError::Execution(nonce))),
    ] {
        assert!(error.matches_exception("TransactionException.NONCE_IS_MAX"));
        assert!(!error.matches_exception("BlockException.INVALID_REQUESTS"));
    }
    for error in [
        BlockFailure::Commitment(Commitment::ReceiptsRoot),
        BlockFailure::Other("decode".into()),
        BlockFailure::Execution(Box::new(BlockExecutionError::MissingWitness(
            WitnessDbError::Account {
                address: H160::zero(),
            },
        ))),
        BlockFailure::Execution(Box::new(BlockExecutionError::ExecutionFailed(
            aurora_evm::ExitReason::Fatal(aurora_evm::ExitFatal::UnhandledInterrupt),
        ))),
    ] {
        assert!(!error.matches_exception("TransactionException.NONCE_IS_MAX"));
        assert!(!error.matches_exception("BlockException.SYSTEM_CONTRACT_EMPTY"));
    }
    assert!(
        BlockFailure::Commitment(Commitment::RequestsHash)
            .matches_exception("BlockException.INVALID_REQUESTS")
    );
    assert!(
        !BlockFailure::Commitment(Commitment::StateRoot)
            .matches_exception("BlockException.INVALID_REQUESTS")
    );
    assert!(BlockFailure::Other("decode".into()).matches_exception(
        "BlockException.RLP_STRUCTURES_ENCODING|TransactionException.TYPE_3_TX_CONTRACT_CREATION",
    ));
    assert!(!BlockFailure::Other("decode".into()).matches_exception("BlockException.UNKNOWN"));
    // Signatures are rejected while decoding or recovering senders, oversized blocks by consensus.
    for stage in ["decode", "recover"] {
        assert!(BlockFailure::Other(stage.into()).matches_exception(
            "TransactionException.INVALID_SIGNATURE_VRS|TransactionException.INVALID_CHAINID",
        ));
    }
    assert!(
        BlockFailure::Other("consensus".into())
            .matches_exception("BlockException.RLP_BLOCK_LIMIT_EXCEEDED")
    );
    for exception in [
        "TransactionException.INVALID_SIGNATURE_VRS",
        "BlockException.RLP_BLOCK_LIMIT_EXCEEDED",
    ] {
        assert!(!BlockFailure::Commitment(Commitment::StateRoot).matches_exception(exception));
    }
}

/// Transition networks switch forks and blob parameters exactly at their transition timestamp.
#[test]
fn transition_networks_switch_at_the_transition_timestamp() {
    let fork = |target: u64, max: u64, fraction: u64| {
        serde_json::json!({
            "target": format!("{target:#x}"),
            "max": format!("{max:#x}"),
            "baseFeeUpdateFraction": format!("{fraction:#x}"),
        })
    };
    // EEST tests@v20.0.2 values; BPO3 has no crate constants.
    let schedule = serde_json::json!({
        "Cancun": fork(3, 6, 3_338_477),
        "Prague": fork(6, 9, 5_007_716),
        "Osaka": fork(6, 9, 5_007_716),
        "BPO1": fork(10, 15, 8_346_193),
        "BPO2": fork(14, 21, 11_684_671),
        "BPO3": fork(21, 32, 20_609_697),
    });
    let active = |network: &str, timestamp| {
        let resolved = chain_spec(network, 1, &schedule)
            .unwrap()
            .active_spec_at_timestamp(timestamp)
            .unwrap();
        (resolved.spec(), resolved.blob_params())
    };
    let before = TRANSITION_TIMESTAMP - 1;
    let bpo3 = BlobParams {
        target_blob_count: 21,
        max_blob_count: 32,
        update_fraction: 20_609_697,
        ..BlobParams::osaka()
    };
    for (network, from, to) in [
        (
            "CancunToPragueAtTime15k",
            (Spec::Cancun, BlobParams::cancun()),
            (Spec::Prague, BlobParams::prague()),
        ),
        (
            "PragueToOsakaAtTime15k",
            (Spec::Prague, BlobParams::prague()),
            (Spec::Osaka, BlobParams::osaka()),
        ),
        (
            "OsakaToBPO1AtTime15k",
            (Spec::Osaka, BlobParams::osaka()),
            (Spec::Osaka, BlobParams::bpo1()),
        ),
        (
            "BPO1ToBPO2AtTime15k",
            (Spec::Osaka, BlobParams::bpo1()),
            (Spec::Osaka, BlobParams::bpo2()),
        ),
        (
            "BPO2ToBPO3AtTime15k",
            (Spec::Osaka, BlobParams::bpo2()),
            (Spec::Osaka, bpo3),
        ),
    ] {
        assert_eq!(active(network, before), from, "{network}");
        assert_eq!(active(network, TRANSITION_TIMESTAMP), to, "{network}");
    }
    assert!(chain_spec("ShanghaiToCancunAtTime15k", 1, &schedule).is_none());
}

/// Why a fixture block did not behave as the fixture says.
enum Failure {
    /// A block marked `expectException` was executed and matched its header.
    AcceptedInvalid { exception: String },
    /// A valid block was rejected.
    RejectedValid { error: String },
    /// An invalid block failed outside the stages permitted by its expected exception.
    WrongRejection { exception: String, error: String },
    /// A valid block executed with a different commitment than its header carries.
    Mismatch { field: &'static str },
    /// The final state differs from `postState`.
    PostState { address: H160 },
    /// A controlled header mutation was accepted or rejected for the wrong reason.
    Mutation { error: String },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AcceptedInvalid { exception } => {
                write!(f, "accepted a block expected to fail with {exception}")
            }
            Self::RejectedValid { error } => write!(f, "rejected a valid block: {error}"),
            Self::WrongRejection { exception, error } => {
                write!(
                    f,
                    "expected {exception}, got an unrelated rejection: {error}"
                )
            }
            Self::Mismatch { field } => write!(f, "{field} mismatch"),
            Self::PostState { address } => write!(f, "post-state differs at {address:?}"),
            Self::Mutation { error } => write!(f, "header mutation: {error}"),
        }
    }
}

struct Outcome {
    blocks: usize,
    transactions: usize,
    negative_blocks: usize,
    /// Valid blocks rejected because the withheld node was needed (withholding mode only).
    withheld_rejections: usize,
    mutated_headers: usize,
    failures: Vec<(String, usize, Failure)>,
}

/// Resolves a fixture's supported network and chain parameters.
fn fixture_chain_spec(fixture: &Value) -> Option<ChainSpec> {
    chain_spec(
        fixture["network"].as_str().unwrap(),
        u64::try_from(hex_u256(&fixture["config"]["chainid"])).unwrap(),
        &fixture["config"]["blobSchedule"],
    )
}

/// Runs one fixture; `None` when its network is not executable here.
fn run_fixture(mode: Mode, name: &str, fixture: &Value, outcome: &mut Outcome) -> Option<()> {
    let chain = fixture_chain_spec(fixture)?;
    let mut state = state_from_json(&fixture["pre"]);
    let genesis = Block::decode_exact(&hex_bytes(&fixture["genesisRLP"])).unwrap();
    let mut recent_headers: Vec<Vec<u8>> = vec![rlp::encode(&genesis.header).to_vec()];
    let mut last_hash = genesis.header.hash_slow();

    for (index, block) in fixture["blocks"].as_array().unwrap().iter().enumerate() {
        let exception = block.get("expectException").and_then(Value::as_str);
        let raw = hex_bytes(&block["rlp"]);
        let window_start = recent_headers.len().saturating_sub(256);
        // Negative cases need complete evidence to test their rejection reason.
        let block_mode = if mode == Mode::WitnessWithholding && exception.is_some() {
            Mode::Witness
        } else {
            mode
        };
        let result = execute_block(
            block_mode,
            &chain,
            &raw,
            &recent_headers[window_start..],
            &state,
        );
        if mode == Mode::WitnessWithholding
            && let Err(error) = &result
            && exception.is_none()
        {
            // execute_block has already restricted this to the exact withheld node.
            if error.is_unproven() {
                outcome.withheld_rejections += 1;
                // The state after a rejected block is unknown here; stop this fixture.
                return Some(());
            }
        }
        match (result, exception) {
            (Err(error), Some(exception)) => {
                if !error.matches_exception(exception) {
                    outcome.failures.push((
                        name.to_owned(),
                        index,
                        Failure::WrongRejection {
                            exception: exception.to_owned(),
                            error: error.to_string(),
                        },
                    ));
                    return Some(());
                }
                outcome.negative_blocks += 1;
            }
            (Err(error), None) => {
                outcome.failures.push((
                    name.to_owned(),
                    index,
                    Failure::RejectedValid {
                        error: error.to_string(),
                    },
                ));
                return Some(());
            }
            (Ok(_), Some(exception)) => {
                outcome.failures.push((
                    name.to_owned(),
                    index,
                    Failure::AcceptedInvalid {
                        exception: exception.to_owned(),
                    },
                ));
                return Some(());
            }

            (Ok((header, post_state)), None) => {
                if mode == Mode::WitnessMutations {
                    match check_header_mutations(
                        &raw,
                        &chain,
                        &recent_headers[window_start..],
                        &state,
                    ) {
                        Ok(count) => outcome.mutated_headers += count,
                        Err(error) => {
                            outcome.failures.push((
                                name.to_owned(),
                                index,
                                Failure::Mutation { error },
                            ));
                            return Some(());
                        }
                    }
                }
                outcome.blocks += 1;
                outcome.transactions += block["transactions"].as_array().map_or(0, Vec::len);
                last_hash = header.hash_slow();
                recent_headers.push(rlp::encode(&header).to_vec());
                state = post_state;
            }
        }
    }

    if let Err(failure) = check_final_state(&state, fixture, last_hash) {
        outcome
            .failures
            .push((name.to_owned(), usize::MAX, failure));
    }
    Some(())
}

/// Checks the exact final account set and the last accepted block's hash.
fn check_final_state(
    state: &BTreeMap<H160, MemoryAccount>,
    fixture: &Value,
    last_hash: H256,
) -> Result<(), Failure> {
    let expected = state_from_json(&fixture["postState"]);
    for (address, account) in &expected {
        if state.get(address) != Some(account) {
            return Err(Failure::PostState { address: *address });
        }
    }
    for address in state.keys() {
        if !expected.contains_key(address) {
            return Err(Failure::PostState { address: *address });
        }
    }
    if hex_h256(&fixture["lastblockhash"]) != last_hash {
        return Err(Failure::Mismatch {
            field: "lastblockhash",
        });
    }
    Ok(())
}

/// Decodes, validates and executes one block over `state`, checking every header commitment
/// derived from execution. Stateless errors retain their type for witness classification.
fn execute_block(
    mode: Mode,
    chain: &ChainSpec,
    raw: &[u8],
    recent_headers: &[Vec<u8>],
    state: &BTreeMap<H160, MemoryAccount>,
) -> Result<(Header, BTreeMap<H160, MemoryAccount>), BlockFailure> {
    let block = Block::decode_exact(raw).map_err(|error| format!("decode: {error}"))?;
    let recovered = recover_block(block).map_err(|error| format!("recover: {error}"))?;
    let header = recovered.header().clone();
    let post_state = match mode {
        Mode::CompleteState => {
            let ancestors = derive_ancestors(recovered.header(), recent_headers)
                .map_err(|error| format!("ancestors: {error}"))?;
            let active_spec =
                crate::block::validate_block_consensus(chain, &recovered, ancestors.parent())
                    .map_err(|error| format!("consensus: {error}"))?;
            let (_parent, ancestor_hashes) = ancestors.split();
            let ExecutionParts {
                withdrawals,
                transactions,
                ..
            } = recovered
                .into_execution_parts()
                .map_err(|error| format!("recovery: {error}"))?;
            let block_env = BlockEnv::from_block(&header, withdrawals, active_spec)
                .map_err(|error| format!("env: {error}"))?;
            let backend = WitnessBackend::from_full_state(
                block_env.vicinity(chain.chain_id),
                state.clone(),
                ancestor_hashes,
            );
            let output = BlockExecutor::new_with_active_spec(
                chain.clone(),
                block_env,
                transactions,
                backend,
                active_spec,
            )
            .execute()
            .map_err(|error| BlockFailure::Execution(Box::new(error)))?;
            let post_state = fold_post_state(BTreeMap::new(), output.state);
            check_commitments(&header, &output.result, &post_state)
                .map_err(BlockFailure::Commitment)?;
            post_state
        }
        Mode::Witness | Mode::WitnessWithholding | Mode::WitnessMutations => {
            let (_root, mut witness) = witness_of(state);
            let withheld = if mode == Mode::WitnessWithholding && !witness.state.is_empty() {
                // Deterministic per block: the header hash picks the node to withhold.
                let pick = witness_node_index(header.hash_slow(), witness.state.len());
                Some(keccak256(&witness.state.remove(pick)))
            } else {
                None
            };
            witness.headers = recent_headers.to_vec();
            let output = stateless_validation_recovered(recovered, witness, chain.clone())
                .map_err(|error| {
                    if mode == Mode::WitnessWithholding && !is_withheld_node_error(&error, withheld)
                    {
                        BlockFailure::Oracle(format!("unexpected withholding rejection: {error:?}"))
                    } else {
                        BlockFailure::Stateless(Box::new(error))
                    }
                })?;
            let post_state = fold_post_state(state.clone(), output.execution_output.state);
            // Production already established sparse_root == header.state_root. Compare that
            // accepted root to an independent full trie, without running the sparse builder twice.
            check_full_state_root(header.state_root, &post_state)?;
            post_state
        }
    };

    Ok((header, post_state))
}

fn check_full_state_root(
    expected: H256,
    state: &BTreeMap<H160, MemoryAccount>,
) -> Result<(), BlockFailure> {
    let got = state_root(state);
    if got != expected {
        return Err(BlockFailure::Oracle(format!(
            "sparse/full post-state root: got {got:?}, expected {expected:?}"
        )));
    }
    Ok(())
}

/// Only the removed node may be unavailable; malformed data and unrelated gaps are failures.
fn is_withheld_node_error(error: &StatelessValidationError, withheld: Option<H256>) -> bool {
    let Some(withheld) = withheld else {
        return false;
    };
    matches!(error,
        StatelessValidationError::Execution(BlockExecutionError::MissingWitness(WitnessDbError::BlindedNode { hash })) if *hash == withheld
    ) || matches!(error,
        StatelessValidationError::Witness(WitnessStateError::PreStateRootNotRevealed { pre_state_root }) if *pre_state_root == withheld
    )
}

/// Compares every commitment the header derives from execution with the execution output.
fn check_commitments(
    header: &Header,
    result: &BlockExecutionResult,
    post_state: &BTreeMap<H160, MemoryAccount>,
) -> Result<(), Commitment> {
    if result.gas_used != header.gas_used {
        return Err(Commitment::GasUsed);
    }
    if result.blob_gas_used != header.blob_gas_used.unwrap_or_default() {
        return Err(Commitment::BlobGasUsed);
    }
    if receipts_root(&result.receipts) != header.receipts_root {
        return Err(Commitment::ReceiptsRoot);
    }
    let mut bloom = Bloom::zero();
    for receipt in &result.receipts {
        bloom.accrue_bloom(&receipt.bloom);
    }
    if bloom != header.logs_bloom {
        return Err(Commitment::LogsBloom);
    }
    if let Some(expected) = header.requests_hash
        && result.requests.requests_hash() != expected
    {
        return Err(Commitment::RequestsHash);
    }
    if state_root(post_state) != header.state_root {
        return Err(Commitment::StateRoot);
    }
    Ok(())
}

fn run_all(mode: Mode) {
    let directory =
        std::env::var("EEST_PATH").expect("set EEST_PATH to the EEST tests@v20.0.2 fixtures");
    let mut paths = Vec::new();
    collect_files(&Path::new(&directory).join("blockchain_tests"), &mut paths);
    assert!(!paths.is_empty(), "no EEST blockchain fixtures found");
    paths.sort();
    let only = std::env::var("EEST_FILTER").ok();

    let mut outcome = Outcome {
        blocks: 0,
        transactions: 0,
        negative_blocks: 0,
        withheld_rejections: 0,
        mutated_headers: 0,
        failures: Vec::new(),
    };
    let (mut fixtures, mut skipped) = (0usize, 0usize);
    for path in paths {
        if let Some(filter) = &only
            && !path.to_string_lossy().contains(filter.as_str())
        {
            continue;
        }
        let json: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for (name, fixture) in json.as_object().unwrap() {
            match run_fixture(mode, name, fixture, &mut outcome) {
                Some(()) => fixtures += 1,
                None => skipped += 1,
            }
        }
    }
    for (name, index, failure) in outcome.failures.iter().take(40) {
        eprintln!("FAIL {name} block {index}: {failure}");
    }
    eprintln!(
        "fixtures={fixtures}, skipped_networks={skipped}, blocks={}, transactions={}, negative_blocks={}, withheld_rejections={}, mutated_headers={}, failures={}",
        outcome.blocks,
        outcome.transactions,
        outcome.negative_blocks,
        outcome.withheld_rejections,
        outcome.mutated_headers,
        outcome.failures.len()
    );
    assert!(outcome.failures.is_empty());
    assert!(outcome.blocks > 0 && outcome.transactions > 0);
    if mode == Mode::WitnessMutations {
        assert!(outcome.mutated_headers >= outcome.blocks * 4);
    }
}

#[test]
#[ignore = "requires EEST_PATH pointing to the official fixtures release"]
fn eest_blockchain_tests_reject_mutated_commitments() {
    run_all(Mode::WitnessMutations);
}

#[test]
#[ignore = "requires EEST_PATH pointing to the official fixtures release"]
fn eest_blockchain_tests_execute_in_complete_state_mode() {
    run_all(Mode::CompleteState);
}

#[test]
#[ignore = "requires EEST_PATH pointing to the official fixtures release"]
fn eest_blockchain_tests_validate_against_witnesses() {
    run_all(Mode::Witness);
}

/// Withholding one node per block must never produce a silently wrong result: every valid block
/// is either rejected as unprovable or matches its header exactly.
#[test]
#[ignore = "requires EEST_PATH pointing to the official fixtures release"]
fn eest_blockchain_tests_never_answer_from_a_withheld_node() {
    run_all(Mode::WitnessWithholding);
}

/// Selects across the whole witness using all hash bytes, including on 32-bit hosts.
fn witness_node_index(hash: H256, len: usize) -> usize {
    usize::try_from(U256::from_big_endian(hash.as_bytes()) % U256::from(len)).unwrap()
}

#[test]
fn withholding_can_select_beyond_the_first_256_nodes() {
    for index in 0..1024usize {
        assert_eq!(
            witness_node_index(H256(U256::from(index).to_big_endian()), 1024),
            index
        );
    }
    assert!(witness_node_index(H256::repeat_byte(0xff), 1023) < 1023);
}

#[test]
fn withholding_accepts_only_the_exact_removed_node() {
    let hash = H256::repeat_byte(1);
    let missing = |hash| {
        StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
            WitnessDbError::BlindedNode { hash },
        ))
    };
    assert!(is_withheld_node_error(&missing(hash), Some(hash)));
    assert!(!is_withheld_node_error(&missing(hash), None));
    assert!(!is_withheld_node_error(&missing(H256::zero()), Some(hash)));
    assert!(is_withheld_node_error(
        &StatelessValidationError::Witness(WitnessStateError::PreStateRootNotRevealed {
            pre_state_root: hash
        }),
        Some(hash)
    ));
    for error in [
        StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
            WitnessDbError::MalformedNode { hash },
        )),
        StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
            WitnessDbError::Code {
                address: H160::zero(),
                code_hash: hash,
            },
        )),
        StatelessValidationError::StateRoot(crate::trie::StateRootError::NoTrie),
        StatelessValidationError::PostExecution(BlockExecutionError::StateRootMismatch {
            got: hash,
            expected: H256::zero(),
        }),
    ] {
        assert!(!is_withheld_node_error(&error, Some(hash)), "{error:?}");
    }
}

#[test]
fn full_state_oracle_rejects_an_incorrect_accepted_root() {
    let state = BTreeMap::from([(
        H160::repeat_byte(1),
        MemoryAccount {
            balance: U256::one(),
            ..MemoryAccount::default()
        },
    )]);
    assert!(check_full_state_root(state_root(&state), &state).is_ok());
    let error = check_full_state_root(crate::constants::EMPTY_ROOT_HASH, &state).unwrap_err();
    assert_eq!(error.stage(), FailureStage::Internal);
    assert!(!error.is_unproven());
}
