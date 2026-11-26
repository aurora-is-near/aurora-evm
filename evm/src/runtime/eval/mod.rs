mod system;

use crate::core::utils::{U256_ONE, U256_ZERO};
use crate::prelude::*;
use crate::{CallScheme, ExitReason, Handler, Opcode, Runtime};
use core::cmp::min;
use primitive_types::{H160, H256, U256};

pub enum Control<H: Handler> {
    Continue,
    CallInterrupt(H::CallInterrupt),
    CreateInterrupt(H::CreateInterrupt),
    Exit(ExitReason),
}

fn handle_other<H: Handler>(state: &mut Runtime, opcode: Opcode, handler: &mut H) -> Control<H> {
    match handler.other(opcode, &mut state.machine) {
        Ok(()) => Control::Continue,
        Err(e) => Control::Exit(e.into()),
    }
}

pub fn eval<H: Handler>(state: &mut Runtime, opcode: Opcode, handler: &mut H) -> Control<H> {
    match opcode {
        Opcode::SHA3 => system::sha3(state),
        Opcode::ADDRESS => system::address(state),
        Opcode::BALANCE => system::balance(state, handler),
        Opcode::SELFBALANCE => system::selfbalance(state, handler),
        Opcode::ORIGIN => system::origin(state, handler),
        Opcode::CALLER => system::caller(state),
        Opcode::CALLVALUE => system::callvalue(state),
        Opcode::GASPRICE => system::gasprice(state, handler),
        Opcode::EXTCODESIZE => system::extcodesize(state, handler),
        Opcode::EXTCODEHASH => system::extcodehash(state, handler),
        Opcode::EXTCODECOPY => system::extcodecopy(state, handler),
        Opcode::RETURNDATASIZE => system::returndatasize(state),
        Opcode::RETURNDATACOPY => system::returndatacopy(state),
        Opcode::BLOCKHASH => system::blockhash(state, handler),
        Opcode::COINBASE => system::coinbase(state, handler),
        Opcode::TIMESTAMP => system::timestamp(state, handler),
        Opcode::NUMBER => system::number(state, handler),
        Opcode::PREVRANDAO => system::prevrandao(state, handler),
        Opcode::GASLIMIT => system::gaslimit(state, handler),
        Opcode::SLOAD => system::sload(state, handler),
        Opcode::SSTORE => system::sstore(state, handler),
        Opcode::GAS => system::gas(state, handler),
        Opcode::LOG0 => system::log(state, 0, handler),
        Opcode::LOG1 => system::log(state, 1, handler),
        Opcode::LOG2 => system::log(state, 2, handler),
        Opcode::LOG3 => system::log(state, 3, handler),
        Opcode::LOG4 => system::log(state, 4, handler),
        Opcode::SELFDESTRUCT => system::selfdestruct(state, handler),
        Opcode::CREATE => system::create(state, false, handler),
        Opcode::CREATE2 => system::create(state, true, handler),
        Opcode::CALL => system::call(state, CallScheme::Call, handler),
        Opcode::CALLCODE => system::call(state, CallScheme::CallCode, handler),
        Opcode::DELEGATECALL => system::call(state, CallScheme::DelegateCall, handler),
        Opcode::STATICCALL => system::call(state, CallScheme::StaticCall, handler),
        Opcode::CHAINID => system::chainid(state, handler),
        Opcode::BASEFEE => system::base_fee(state, handler),
        Opcode::BLOBBASEFEE => system::blob_base_fee(state, handler),
        Opcode::BLOBHASH => system::blob_hash(state, handler),
        Opcode::TLOAD => system::tload(state, handler),
        Opcode::TSTORE => system::tstore(state, handler),
        Opcode::MCOPY => system::mcopy(state, handler),
        _ => handle_other(state, opcode, handler),
    }
}

pub fn finish_create(
    runtime: &mut Runtime,
    reason: ExitReason,
    address: Option<H160>,
    return_data: Vec<u8>,
) -> Result<(), ExitReason> {
    runtime.return_data_buffer = return_data;
    let create_address: H256 = address.map_or_default(Into::into);

    match reason {
        ExitReason::Succeed(_) => {
            runtime
                .machine
                .stack_mut()
                .push(U256::from_big_endian(&create_address[..]))?;
            Ok(())
        }
        ExitReason::Revert(_) | ExitReason::Error(_) => {
            runtime.machine.stack_mut().push(U256_ZERO)?;
            Ok(())
        }
        ExitReason::Fatal(e) => {
            runtime.machine.stack_mut().push(U256_ZERO)?;
            Err(e.into())
        }
    }
}

pub fn finish_call(
    runtime: &mut Runtime,
    out_len: usize,
    out_offset: usize,
    reason: ExitReason,
    return_data: Vec<u8>,
) -> Result<(), ExitReason> {
    runtime.return_data_buffer = return_data;
    let target_len = min(out_len, runtime.return_data_buffer.len());

    match reason {
        ExitReason::Succeed(_) => {
            runtime.machine.memory_mut().copy_data(
                out_offset,
                U256_ZERO,
                target_len,
                &runtime.return_data_buffer,
            )?;
            runtime.machine.stack_mut().push(U256_ONE)?;
            Ok(())
        }
        ExitReason::Revert(_) => {
            // A reverted child can still return data to its caller.
            runtime.machine.memory_mut().copy_data(
                out_offset,
                U256_ZERO,
                target_len,
                &runtime.return_data_buffer,
            )?;
            runtime.machine.stack_mut().push(U256_ZERO)?;
            Ok(())
        }
        ExitReason::Error(_) => {
            runtime.machine.stack_mut().push(U256_ZERO)?;

            Ok(())
        }
        ExitReason::Fatal(e) => {
            runtime.machine.stack_mut().push(U256_ZERO)?;

            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::finish_call;
    use crate::prelude::Rc;
    use crate::{Context, ExitFatal, ExitReason, ExitRevert, ExitSucceed, Runtime};
    use primitive_types::{H160, U256};

    fn assert_copy_failure_before_status(reason: ExitReason) {
        let context = Context {
            address: H160::zero(),
            caller: H160::zero(),
            apparent_value: U256::zero(),
        };
        let mut runtime = Runtime::new(Rc::default(), Rc::default(), context, 1, 32);

        // Bypass CALL's range check: one output byte at offset 32 exceeds the caller's cap.
        let result = finish_call(&mut runtime, 1, 32, reason, [0xab].into());

        assert_eq!(result, Err(ExitReason::Fatal(ExitFatal::NotSupported)));
        assert!(runtime.machine().stack().is_empty());
    }

    #[test]
    fn success_propagates_output_copy_failure_before_pushing_one() {
        assert_copy_failure_before_status(ExitSucceed::Returned.into());
    }

    #[test]
    fn revert_propagates_output_copy_failure_before_pushing_zero() {
        assert_copy_failure_before_status(ExitRevert::Reverted.into());
    }
}
