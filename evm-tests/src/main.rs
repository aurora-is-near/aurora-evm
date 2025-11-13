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
use std::path::{Path, PathBuf};
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
                    arg!([PATH] "json file or directory for tests run")
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
                    arg!([PATH] "json file or directory for tests run")
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
                    arg!(-p --print_state "When test failed print state")
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
        };
        let mut tests_result = TestExecutionResult::new();
        for src_name in matches.get_many::<PathBuf>("PATH").unwrap() {
            let path = Path::new(src_name);
            assert!(path.exists(), "data source is not exist");
            if path.is_file() {
                run_vm_test_for_file(&verbose_output, path, &mut tests_result);
            } else if path.is_dir() {
                run_vm_test_for_dir(&verbose_output, path, &mut tests_result);
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
        };
        let mut tests_result = TestExecutionResult::new();
        for src_name in matches.get_many::<PathBuf>("PATH").unwrap() {
            let path = Path::new(src_name);

            assert!(
                path.exists(),
                "data source is not exist: {}",
                path.display()
            );
            if path.is_file() {
                run_test_for_file(
                    spec.as_ref(),
                    &verbose_output,
                    path,
                    &mut tests_result,
                    test_name,
                );
            } else if path.is_dir() {
                run_test_for_dir(
                    spec.as_ref(),
                    &verbose_output,
                    path,
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
    }
    Ok(())
}

fn run_vm_test_for_dir(
    verbose_output: &VerboseOutput,
    dir_name: &Path,
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
            run_vm_test_for_dir(verbose_output, path.as_path(), tests_result);
        } else {
            run_vm_test_for_file(verbose_output, path.as_path(), tests_result);
        }
    }
}

fn run_vm_test_for_file(
    verbose_output: &VerboseOutput,
    file_name: &Path,
    tests_result: &mut TestExecutionResult,
) {
    if verbose_output.verbose {
        println!(
            "RUN for: {}",
            short_test_file_name(file_name.to_str().unwrap())
        );
    }

    let file = File::open(file_name).expect("Open file failed");
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
                    short_test_file_name(file_name.to_str().unwrap())
                );
            } else if verbose_output.verbose_failed {
                println!(
                    "RUN for: {}",
                    short_test_file_name(file_name.to_str().unwrap())
                );
                println!("Tests count:\t{}", test_res.total);
                println!(
                    "Failed:\t\t{} - {}\n",
                    test_res.failed,
                    short_test_file_name(file_name.to_str().unwrap())
                );
            }
        } else if verbose_output.verbose {
            println!("Tests count: {}\n", test_res.total);
        }

        tests_result.merge(test_res);
    }
}

fn run_test_for_dir(
    spec: Option<&Spec>,
    verbose_output: &VerboseOutput,
    dir_name: &Path,
    tests_result: &mut TestExecutionResult,
    test_name: Option<&String>,
) {
    if should_skip(dir_name) {
        println!("Skipping test case {}", dir_name.display());
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
            run_test_for_dir(
                spec,
                verbose_output,
                path.as_path(),
                tests_result,
                test_name,
            );
        } else {
            run_test_for_file(
                spec,
                verbose_output,
                path.as_path(),
                tests_result,
                test_name,
            );
        }
    }
}

fn run_test_for_file(
    spec: Option<&Spec>,
    verbose_output: &VerboseOutput,
    file_name: &Path,
    tests_result: &mut TestExecutionResult,
    test_name: Option<&String>,
) {
    if should_skip(file_name) {
        if verbose_output.verbose {
            println!("Skipping test case {}", file_name.display());
        }
        return;
    }
    if verbose_output.verbose {
        println!(
            "RUN for: {}",
            short_test_file_name(file_name.to_str().unwrap())
        );
    }
    let file = File::open(file_name).expect("Open file failed");
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
            file_name: file_name.to_path_buf(),
            name,
        };
        let test_res = state::test(test_config, test);

        if test_res.failed > 0 {
            if verbose_output.verbose {
                println!("Tests count:\t{}", test_res.total);
                println!(
                    "Failed:\t\t{} - {}\n",
                    test_res.failed,
                    short_test_file_name(file_name.to_str().unwrap())
                );
            } else if verbose_output.verbose_failed {
                println!(
                    "RUN for: {}",
                    short_test_file_name(file_name.to_str().unwrap())
                );
                println!("Tests count:\t{}", test_res.total);
                println!(
                    "Failed:\t\t{} - {}\n",
                    test_res.failed,
                    short_test_file_name(file_name.to_str().unwrap())
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
/// - `path/with/sub/path` - recursively check path
fn should_skip(path: &Path) -> bool {
    let matches = |case: &str| {
        let case_path = Path::new(case);
        let case_path_components: Vec<_> = case_path.components().collect();
        let path_components: Vec<_> = path.components().collect();
        let case_path_len = case_path_components.len();
        let path_len = path_components.len();

        // Check path length without file name
        if case_path_len > path_len {
            return false;
        }
        // Check stem file name (without extension)
        if let (Some(file_path_stem), Some(case_file_path_stem)) =
            (path.file_stem(), case_path.file_stem())
        {
            if file_path_stem == case_file_path_stem {
                // If case path contains only file name
                if case_path_len == 1 {
                    return true;
                }
                // Check sub path without file names
                if case_path_len > 1
                    && path_len > 1
                    && case_path_components[..case_path_len - 1]
                        == path_components[path_len - case_path_len..path_len - 1]
                {
                    return true;
                }
            }
        }
        // Check recursively path from the end without file name
        if case_path_len < path_len && path_len > 1 {
            for i in 1..=path_len - case_path_len {
                if case_path_components
                    == path_components[path_len - case_path_len - i..path_len - i]
                {
                    return true;
                }
            }
        }
        false
    };

    SKIPPED_CASES.iter().any(|case| matches(case))
}
