//! Opt-in differential over the EEST blockchain fixtures.
//!
//! Every fixture starts from its `pre` allocation. Each block is decoded, recovered, validated
//! against its verified ancestors, executed, and its header commitments recomputed from the
//! execution output; `expectException` must fail at a stage allowed by that exception. The final
//! state is compared with `postState`. Only Cancun-or-later networks are executable here.
//!
//! Two modes share the checks: complete-state mode drives the executor over the full state, and
//! witness mode runs the production [`stateless_validation_recovered`] path against a witness
//! derived from that state — a superset of every node the block needs, so no read may be unproven.

use crate::block::{Block, BlockEnv, ExecutionParts, Header, derive_ancestors, recover_block};
use crate::bloom::Bloom;
use crate::chain_spec::ChainSpec;
use crate::eips::eip1559::BaseFeeParams;
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

/// The chain configuration of a fixture network, `None` for networks this crate cannot execute.
fn chain_spec(network: &str, chain_id: u64) -> Option<ChainSpec> {
    let (spec, timestamps): (Spec, Vec<(Spec, u64)>) = match network {
        "Cancun" => (Spec::Cancun, vec![(Spec::Cancun, 0)]),
        "Prague" => (Spec::Prague, vec![(Spec::Cancun, 0), (Spec::Prague, 0)]),
        "CancunToPragueAtTime15k" => (
            Spec::Prague,
            vec![(Spec::Cancun, 0), (Spec::Prague, 15_000)],
        ),
        _ => return None,
    };
    Some(ChainSpec {
        chain_id,
        spec,
        hard_forks_timestamps: timestamps.into_iter().collect(),
        deposit_contract_address: None,
        base_fee_params: BaseFeeParams::ethereum(),
        blob_schedule: BlobScheduleBlobParams::mainnet(),
    })
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
    let WitnessState { accounts, codes } = state;
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
}

/// Keeps stateless errors typed until the fixture result has been classified.
enum BlockFailure {
    Stateless(Box<StatelessValidationError>),
    Execution(Box<BlockExecutionError>),
    Commitment(Commitment),
    Other(String),
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
                _ => FailureStage::PreExecution,
            },
            Self::Execution(error) => execution_failure_stage(error),
            Self::Commitment(_) => FailureStage::Commitment,
            Self::Other(_) => FailureStage::PreExecution,
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
                }
                "BlockException.RLP_STRUCTURES_ENCODING"
                | "BlockException.BLOB_GAS_USED_ABOVE_LIMIT"
                | "BlockException.INCORRECT_BLOB_GAS_USED"
                | "BlockException.INCORRECT_EXCESS_BLOB_GAS"
                | "BlockException.INVALID_BASEFEE_PER_GAS"
                | "BlockException.INVALID_GASLIMIT"
                | "BlockException.INVALID_WITHDRAWALS_ROOT"
                | "BlockException.INVALID_BLOCK_HASH" => stage == FailureStage::PreExecution,
                // Fixed-width destinations are checked by the codec; block blob limits also
                // have a header-level check before transaction execution.
                "TransactionException.TYPE_3_TX_CONTRACT_CREATION"
                | "TransactionException.TYPE_4_TX_CONTRACT_CREATION"
                | "TransactionException.TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED"
                | "TransactionException.TYPE_3_TX_BLOB_COUNT_EXCEEDED" => {
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
            Self::Other(error) => f.write_str(error),
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
        }
    }
}

struct Outcome {
    blocks: usize,
    transactions: usize,
    negative_blocks: usize,
    /// Valid blocks rejected because the withheld node was needed (withholding mode only).
    withheld_rejections: usize,
    failures: Vec<(String, usize, Failure)>,
}

/// Runs one fixture; `None` when its network is not executable here.
fn run_fixture(mode: Mode, name: &str, fixture: &Value, outcome: &mut Outcome) -> Option<()> {
    let chain_id = u64::try_from(hex_u256(&fixture["config"]["chainid"])).unwrap();
    let chain = chain_spec(fixture["network"].as_str().unwrap(), chain_id)?;

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
            // The only acceptable rejection of a valid block is an unprovable read.
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
    let (result, post_state) = match mode {
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
            (
                output.result,
                fold_post_state(BTreeMap::new(), output.state),
            )
        }
        Mode::Witness | Mode::WitnessWithholding => {
            let (_root, mut witness) = witness_of(state);
            if mode == Mode::WitnessWithholding && !witness.state.is_empty() {
                // Deterministic per block: the header hash picks the node to withhold.
                let pick = witness_node_index(header.hash_slow(), witness.state.len());
                witness.state.remove(pick);
            }
            witness.headers = recent_headers.to_vec();
            let output = stateless_validation_recovered(recovered, witness, chain.clone())
                .map_err(|error| BlockFailure::Stateless(Box::new(error)))?;
            (
                output.execution_output.result,
                fold_post_state(state.clone(), output.execution_output.state),
            )
        }
    };
    check_commitments(&header, &result, &post_state).map_err(BlockFailure::Commitment)?;
    Ok((header, post_state))
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
    let directory = std::env::var("EEST_PATH").expect("set EEST_PATH to fixtures_stable-v5.4.0");
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
        "fixtures={fixtures}, skipped_networks={skipped}, blocks={}, transactions={}, negative_blocks={}, withheld_rejections={}, failures={}",
        outcome.blocks,
        outcome.transactions,
        outcome.negative_blocks,
        outcome.withheld_rejections,
        outcome.failures.len()
    );
    assert!(outcome.failures.is_empty());
    assert!(outcome.blocks > 0 && outcome.transactions > 0);
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
