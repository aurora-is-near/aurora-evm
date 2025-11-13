use crate::config::VerboseOutput;
use crate::execution_results::TestExecutionResult;
use crate::types::VmTestCase;
use aurora_evm::backend::{ApplyBackend, MemoryBackend};
use aurora_evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use aurora_evm::Config;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::rc::Rc;

#[must_use]
pub fn test(verbose_output: &VerboseOutput, name: &str, test: &VmTestCase) -> TestExecutionResult {
    let mut result = TestExecutionResult::new();
    let mut failed = false;
    result.total = 1;
    if verbose_output.verbose {
        print!("Running test {name} ... ");
        io::stdout().flush().expect("Could not flush stdout");
    }

    let original_state = test.pre_state.to_memory_accounts_state();
    let vicinity = test.get_memory_vicinity();
    let config = Config::frontier();
    let mut backend = MemoryBackend::new(&vicinity, original_state.0);
    let metadata = StackSubstateMetadata::new(test.get_gas_limit(), &config);
    let state = MemoryStackState::new(metadata, &backend);
    let precompile = BTreeMap::new();
    let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompile);

    let mut runtime = aurora_evm::Runtime::new(
        Rc::new(test.transaction.code.clone()),
        Rc::new(test.transaction.data.clone()),
        test.transaction.get_context(),
        config.stack_limit,
        config.memory_limit,
    );

    let reason = executor.execute(&mut runtime);
    let gas = executor.gas();
    let (values, logs) = executor.into_state().deconstruct();
    backend.apply(values, logs, false);

    if test.output.is_none() {
        if verbose_output.verbose {
            print!("{reason:?} ");
        }

        if reason.is_succeed() {
            failed = true;
            if verbose_output.verbose_failed {
                print!("[Failed: succeed for empty output: {reason:?}] ");
            }
        }
        if !(test.post_state.is_none() && test.gas_left.is_none()) {
            failed = true;
            if verbose_output.verbose_failed {
                print!("[Failed: not empty state and left gas for empty output: {reason:?}] ",);
            }
        }
    } else {
        let expected_post_gas = test.get_gas_left();
        if verbose_output.verbose {
            print!("{reason:?} ");
        }

        if runtime.machine().return_value() != test.get_output() {
            failed = true;
            if verbose_output.verbose_failed {
                print!(
                    "[Failed: wrong return value: {:?}] ",
                    runtime.machine().return_value()
                );
            }
        }

        if !test.validate_state(backend.state()) {
            failed = true;
            if verbose_output.verbose_failed {
                print!("[Failed: invalid state] ");
            }
        }
        if gas != expected_post_gas {
            failed = true;
            if verbose_output.verbose_failed {
                print!("[Failed: unexpected gas: {gas:?}] ");
            }
        }
    }

    if failed {
        result.failed += 1;
        if verbose_output.verbose || verbose_output.verbose_failed {
            println!("failed <-------");
        }
    } else if verbose_output.verbose {
        println!("succeed");
    }
    result
}
