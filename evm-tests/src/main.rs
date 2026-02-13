#![allow(clippy::too_long_first_doc_paragraph, clippy::missing_panics_doc)]

use crate::config::{TestConfig, VerboseOutput};
use crate::execution_results::TestExecutionResult;
use crate::types::Spec;
use crate::types::StateTestCase;
use crate::types::VmTestCase;
use clap::{arg, command, value_parser, ArgAction, Command};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

pub mod state;
pub mod types;
pub mod vm;

mod assertions;
mod config;
mod execution_results;
mod precompiles;
mod state_dump;

#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn main() -> Result<(), String> {
    let matches = command!()
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .subcommand(
            Command::new("vm")
                .about("vm tests runner")
                .arg(
                    arg!([PATH] "JSON file or directory for tests run")
                        .action(ArgAction::Append)
                        .required(true)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    arg!(-v --verbose "Verbose output")
                        .default_value("false")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    arg!(-f --verbose_failed "Verbose failed only output")
                        .default_value("false")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("state")
                .about("state tests runner")
                .arg(
                    arg!([PATH] "JSON file or directory for tests run")
                        .action(ArgAction::Append)
                        .required(true)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    arg!(-n --"test-name" <TEST_NAME> "filer for the test name, for ex: \"test/name\")")
                        .required(false)
                        .value_parser(value_parser!(String))
                )
                .arg(arg!(-s --spec <SPEC> "Ethereum hard fork"))
                .arg(
                    arg!(-v --verbose "Verbose output")
                        .default_value("false")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    arg!(-f --verbose_failed "Verbose failed only output")
                        .default_value("false")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    arg!(-w --very_verbose "Very verbose output")
                        .default_value("false")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    arg!(-p --print_state "Print state when the test fails")
                        .default_value("false")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    arg!(--dump_successful_tx <FILE_NAME> "Optional file name to dump all successful transactions")
                        .required(false)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    arg!(--slow_tests "Print state slow tests")
                        .default_value("false")
                        .action(ArgAction::SetTrue),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("vm") {
        let verbose_output = VerboseOutput {
            verbose: matches.get_flag("verbose"),
            verbose_failed: matches.get_flag("verbose_failed"),
            very_verbose: false,
            print_state: false,
            print_slow: false,
            dump_transactions: None,
        };
        let mut tests_result = TestExecutionResult::new();
        for src_path in matches.get_many::<PathBuf>("PATH").unwrap() {
            assert!(src_path.exists(), "data source does not exist");

            if src_path.is_file() {
                run_vm_test_for_file(&verbose_output, src_path, &mut tests_result);
            } else if src_path.is_dir() {
                run_vm_test_for_dir(&verbose_output, src_path, &mut tests_result);
            }
        }
        println!("\nTOTAL: {}", tests_result.total);
        println!("FAILED: {}\n", tests_result.failed);
        if tests_result.failed != 0 {
            return Err(format!("tests failed: {}", tests_result.failed));
        }
    }

    if let Some(matches) = matches.subcommand_matches("state") {
        let spec: Option<Spec> = matches
            .get_one::<String>("spec")
            .and_then(|spec| Spec::from_str(spec).ok());

        let test_name: Option<&String> = matches.get_one::<String>("test-name");

        let verbose_output = VerboseOutput {
            verbose: matches.get_flag("verbose"),
            verbose_failed: matches.get_flag("verbose_failed"),
            very_verbose: matches.get_flag("very_verbose"),
            print_state: matches.get_flag("print_state"),
            print_slow: matches.get_flag("slow_tests"),
            dump_transactions: matches.get_one::<PathBuf>("dump_successful_tx").cloned(),
        };
        let mut tests_result = TestExecutionResult::new();
        for src_path in matches.get_many::<PathBuf>("PATH").unwrap() {
            assert!(
                src_path.exists(),
                "data source does not exist: {}",
                src_path.display()
            );
            if src_path.is_file() {
                run_test_for_file(
                    spec.as_ref(),
                    &verbose_output,
                    src_path,
                    &mut tests_result,
                    test_name,
                );
            } else if src_path.is_dir() {
                run_test_for_dir(
                    spec.as_ref(),
                    &verbose_output,
                    src_path,
                    &mut tests_result,
                    test_name,
                );
            }
        }
        println!("\nTOTAL: {}", tests_result.total);
        println!("FAILED: {}\n", tests_result.failed);

        if tests_result.failed != 0 {
            return Err(format!("tests failed: {}", tests_result.failed));
        }

        if verbose_output.print_slow {
            println!("SLOW TESTS:");
            tests_result.print_bench();
        }

        if let Some(dunp_to_file) = verbose_output.dump_transactions {
            let txs = tests_result.dump_successful_txs;
            let data = serde_json::to_string(&txs).expect("JSON serialization failed");
            fs::write(&dunp_to_file, data).expect("Unable to write file");
            println!(
                "TEST SUCCESSFUL TRANSACTIONS DUMPED TO: {} [{}]",
                dunp_to_file.display(),
                txs.len()
            );
        }
    }
    Ok(())
}

fn run_vm_test_for_dir<P: AsRef<Path>>(
    verbose_output: &VerboseOutput,
    dir_name: &P,
    tests_result: &mut TestExecutionResult,
) {
    for entry in fs::read_dir(dir_name).unwrap() {
        let entry = entry.unwrap();
        if let Some(s) = entry.file_name().to_str() {
            if s.starts_with('.') {
                continue;
            }
        }
        let path = entry.path();
        if path.is_dir() {
            run_vm_test_for_dir(verbose_output, &path, tests_result);
        } else {
            run_vm_test_for_file(verbose_output, &path, tests_result);
        }
    }
}

fn run_vm_test_for_file<P: AsRef<Path>>(
    verbose_output: &VerboseOutput,
    file_path: &P,
    tests_result: &mut TestExecutionResult,
) {
    let file_name = file_path.as_ref().to_str().unwrap();

    if verbose_output.verbose {
        println!("RUN for: {}", short_test_file_name(file_name));
    }

    let file = File::open(file_path).expect("Open file failed");
    let reader = BufReader::new(file);
    let test_suite = serde_json::from_reader::<_, HashMap<String, VmTestCase>>(reader)
        .expect("Parse test cases failed");

    for (name, test) in test_suite {
        let test_res = vm::test(verbose_output, &name, &test);

        if test_res.failed > 0 {
            if verbose_output.verbose {
                println!("Tests count:\t{}", test_res.total);
                println!(
                    "Failed:\t\t{} - {}\n",
                    test_res.failed,
                    short_test_file_name(file_name)
                );
            } else if verbose_output.verbose_failed {
                println!("RUN for: {}", short_test_file_name(file_name));
                println!("Tests count:\t{}", test_res.total);
                println!(
                    "Failed:\t\t{} - {}\n",
                    test_res.failed,
                    short_test_file_name(file_name)
                );
            }
        } else if verbose_output.verbose {
            println!("Tests count: {}\n", test_res.total);
        }

        tests_result.merge(test_res);
    }
}

fn run_test_for_dir<P: AsRef<Path>>(
    spec: Option<&Spec>,
    verbose_output: &VerboseOutput,
    dir_name: &P,
    tests_result: &mut TestExecutionResult,
    test_name: Option<&String>,
) {
    if should_skip(dir_name.as_ref()) {
        println!("Skipping the test case {}", dir_name.as_ref().display());
        return;
    }
    for entry in fs::read_dir(dir_name).unwrap() {
        let entry = entry.unwrap();
        if let Some(s) = entry.file_name().to_str() {
            if s.starts_with('.') {
                continue;
            }
        }
        let path = entry.path();
        if path.is_dir() {
            run_test_for_dir(spec, verbose_output, &path, tests_result, test_name);
        } else {
            run_test_for_file(spec, verbose_output, &path, tests_result, test_name);
        }
    }
}

fn run_test_for_file<P: AsRef<Path>>(
    spec: Option<&Spec>,
    verbose_output: &VerboseOutput,
    file_path: &P,
    tests_result: &mut TestExecutionResult,
    test_name: Option<&String>,
) {
    if should_skip(file_path.as_ref()) {
        if verbose_output.verbose {
            println!("Skipping the test case {}", file_path.as_ref().display());
        }
        return;
    }
    let file_name = file_path.as_ref().to_str().unwrap();

    if verbose_output.verbose {
        println!("RUN for: {}", short_test_file_name(file_name));
    }

    let file = File::open(file_path).expect("Open file failed");
    let reader = BufReader::new(file);

    let test_suite = serde_json::from_reader::<_, HashMap<String, StateTestCase>>(reader)
        .expect("Parse test cases failed");

    for (name, test) in test_suite {
        if let Some(t) = test_name {
            if !name.contains(t) {
                continue;
            }
        }

        let test_config = TestConfig {
            verbose_output: verbose_output.clone(),
            spec: spec.cloned(),
            file_name: file_path.as_ref().to_path_buf(),
            name,
        };
        let test_res = state::test(test_config, test);

        if test_res.failed > 0 {
            if verbose_output.verbose {
                println!("Tests count:\t{}", test_res.total);
                println!(
                    "Failed:\t\t{} - {}\n",
                    test_res.failed,
                    short_test_file_name(file_name)
                );
            } else if verbose_output.verbose_failed {
                println!("RUN for: {}", short_test_file_name(file_name));
                println!("Tests count:\t{}", test_res.total);
                println!(
                    "Failed:\t\t{} - {}\n",
                    test_res.failed,
                    short_test_file_name(file_name)
                );
            }
        } else if verbose_output.verbose {
            println!("Tests count: {}\n", test_res.total);
        }

        tests_result.merge(test_res);
    }
}

fn short_test_file_name(name: &str) -> String {
    let res: Vec<_> = name.split("GeneralStateTests/").collect();
    if res.len() > 1 {
        res[1].to_string()
    } else {
        res[0].to_string()
    }
}

#[cfg(feature = "enable-slow-tests")]
const SKIPPED_CASES: &[&str] = &[
    // funky test with `bigint 0x00` value in json :) not possible to happen on mainnet and require
    // custom json parser. https://github.com/ethereum/tests/issues/971
    "stTransactionTest/ValueOverflow",
    "stTransactionTest/ValueOverflowParis",
    // It's impossible touch storage by precompiles
    // NOTE: this tests related to hard forks: London and before London
    "stRevertTest/RevertPrecompiledTouch",
    "stRevertTest/RevertPrecompiledTouch_storage",
    // Wrong json fields `s`, `r` for EIP-7702
    "eip7702_set_code_tx/set_code_txs/invalid_tx_invalid_auth_signature",
    // Wrong json field `chain_id` for EIP-7702
    "eip7702_set_code_tx/set_code_txs/tx_validity_nonce",
    // EIP-7702: for non empty storage fails evm state hash check
    "eip7702_set_code_tx/set_code_txs/set_code_to_non_empty_storage",
];

#[cfg(not(feature = "enable-slow-tests"))]
const SKIPPED_CASES: &[&str] = &[
    // funky test with `bigint 0x00` value in json :) not possible to happen on mainnet and require
    // custom json parser. https://github.com/ethereum/tests/issues/971
    "stTransactionTest/ValueOverflow",
    "stTransactionTest/ValueOverflowParis",
    // It's impossible touch storage by precompiles
    // NOTE: this tests related to hard forks: London and before London
    "stRevertTest/RevertPrecompiledTouch",
    "stRevertTest/RevertPrecompiledTouch_storage",
    // These tests pass, but they take a long time to execute, so they are skipped by default.
    "stTimeConsuming/static_Call50000_sha256",
    "vmPerformance/loopMul",
    "stTimeConsuming/CALLBlake2f_MaxRounds",
    // Wrong json fields `s`, `r` for EIP-7702
    "eip7702_set_code_tx/set_code_txs/invalid_tx_invalid_auth_signature",
    // Wrong json field `chain_id` for EIP-7702
    "eip7702_set_code_tx/set_code_txs/tx_validity_nonce",
    // EIP-7702: for non empty storage fails evm state hash check
    "eip7702_set_code_tx/set_code_txs/set_code_to_non_empty_storage",
];

/// Check if a path should be skipped.
/// It checks:
/// - `path/and_file_stem` - check path and file name (without extension)
/// - `path/with/sub/path` - recursively check a path
fn should_skip(path: &Path) -> bool {
    let path_components: Vec<Component<'_>> = path.components().collect();
    let path_len = path_components.len();
    let path_stem = path.file_stem();

    SKIPPED_CASES.iter().any(|case| {
        let case_path = Path::new(case);
        let case_components: Vec<Component<'_>> = case_path.components().collect();
        let case_len = case_components.len();

        if case_len > path_len {
            return false;
        }

        // 1) Match by stem + optional parent suffix match
        if let (Some(ps), Some(cs)) = (path_stem, case_path.file_stem()) {
            if ps == cs {
                if case_len == 1 {
                    return true; // "just a filename (stem)" matches anywhere
                }
                // Compare parent components suffix (excluding the filename)
                if path_len >= case_len
                    && case_components[..case_len - 1]
                        == path_components[path_len - case_len..path_len - 1]
                {
                    return true;
                }
            }
        }

        // 2) Match any contiguous component window (excluding filename semantics)
        if case_len < path_len {
            for start in 0..=(path_len - case_len) {
                if case_components == path_components[start..start + case_len] {
                    return true;
                }
            }
        }

        false
    })
}
