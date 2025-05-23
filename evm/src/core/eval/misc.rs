use super::Control;

use crate::core::utils::USIZE_MAX;
use crate::core::{ExitError, ExitRevert, ExitSucceed, Machine};
use crate::utils::U256_ZERO;
use core::cmp::min;
use primitive_types::{H256, U256};

#[inline]
pub fn codesize(state: &mut Machine) -> Control {
    let size = U256::from(state.code.len());
    push_u256!(state, size);
    Control::Continue(1)
}

#[inline]
pub fn codecopy(state: &mut Machine) -> Control {
    pop_u256!(state, memory_offset, code_offset, len);

    // If `len` is zero then nothing happens, regardless of the
    // value of the other parameters. In particular, `memory_offset`
    // might be larger than `usize::MAX`, hence why we check this first.
    if len == U256_ZERO {
        return Control::Continue(1);
    }
    let len = as_usize_or_fail!(len);
    let memory_offset = as_usize_or_fail!(memory_offset);

    try_or_fail!(state.memory.resize_offset(memory_offset, len));
    match state
        .memory
        .copy_data(memory_offset, code_offset, len, &state.code)
    {
        Ok(()) => Control::Continue(1),
        Err(e) => Control::Exit(e.into()),
    }
}

#[inline]
pub fn calldataload(state: &mut Machine) -> Control {
    pop_u256!(state, index);

    let mut load = [0u8; 32];
    if index <= USIZE_MAX {
        let checked_index = index.as_usize();
        let data_count = state.data.len();
        if checked_index < data_count {
            let count = 32.min(data_count - checked_index);
            load[..count].copy_from_slice(&state.data[checked_index..checked_index + count]);
        }
    }

    push_h256!(state, H256::from(load));
    Control::Continue(1)
}

#[inline]
pub fn calldatasize(state: &mut Machine) -> Control {
    let len = U256::from(state.data.len());
    push_u256!(state, len);
    Control::Continue(1)
}

#[inline]
pub fn calldatacopy(state: &mut Machine) -> Control {
    pop_u256!(state, memory_offset, data_offset, len);

    // See comment on `codecopy` about the `len == 0` case.
    if len == U256_ZERO {
        return Control::Continue(1);
    }
    let len = as_usize_or_fail!(len);
    let memory_offset = as_usize_or_fail!(memory_offset);

    try_or_fail!(state.memory.resize_offset(memory_offset, len));

    match state
        .memory
        .copy_data(memory_offset, data_offset, len, &state.data)
    {
        Ok(()) => Control::Continue(1),
        Err(e) => Control::Exit(e.into()),
    }
}

#[inline]
pub fn pop(state: &mut Machine) -> Control {
    pop_u256!(state, _val);
    Control::Continue(1)
}

#[inline]
pub fn mload(state: &mut Machine) -> Control {
    pop_u256!(state, index);
    let index = as_usize_or_fail!(index);
    try_or_fail!(state.memory.resize_offset(index, 32));
    let value = state.memory.get_h256(index);
    push_h256!(state, value);
    Control::Continue(1)
}

#[inline]
pub fn mstore(state: &mut Machine) -> Control {
    pop_u256!(state, index);
    let index = as_usize_or_fail!(index);
    pop_h256!(state, value);
    try_or_fail!(state.memory.resize_offset(index, 32));
    match state.memory.set(index, &value[..], 32) {
        Ok(()) => Control::Continue(1),
        Err(e) => Control::Exit(e.into()),
    }
}

#[inline]
pub fn mstore8(state: &mut Machine) -> Control {
    pop_u256!(state, index, value);
    let index = as_usize_or_fail!(index);
    try_or_fail!(state.memory.resize_offset(index, 1));
    let value = u8::try_from(value.low_u32() & 0xff).unwrap_or(u8::MAX);
    match state.memory.set(index, &[value], 1) {
        Ok(()) => Control::Continue(1),
        Err(e) => Control::Exit(e.into()),
    }
}

#[inline]
pub fn jump(state: &mut Machine) -> Control {
    pop_u256!(state, dest);
    let dest = as_usize_or_fail!(dest, ExitError::InvalidJump);

    if state.valids.is_valid(dest) {
        Control::Jump(dest)
    } else {
        Control::Exit(ExitError::InvalidJump.into())
    }
}

#[inline]
pub fn jumpi(state: &mut Machine) -> Control {
    pop_u256!(state, dest, value);

    if value == U256_ZERO {
        Control::Continue(1)
    } else {
        let dest = as_usize_or_fail!(dest, ExitError::InvalidJump);
        if state.valids.is_valid(dest) {
            Control::Jump(dest)
        } else {
            Control::Exit(ExitError::InvalidJump.into())
        }
    }
}

#[inline]
pub fn pc(state: &mut Machine, position: usize) -> Control {
    push_u256!(state, U256::from(position));
    Control::Continue(1)
}

#[inline]
pub fn msize(state: &mut Machine) -> Control {
    push_u256!(state, state.memory.effective_len().into());
    Control::Continue(1)
}

#[inline]
pub fn push(state: &mut Machine, n: usize, position: usize) -> Control {
    let end = min(position + 1 + n, state.code.len());
    let slice = &state.code[(position + 1)..end];
    let mut val = [0u8; 32];
    val[(32 - n)..(32 - n + slice.len())].copy_from_slice(slice);
    let val = U256::from_big_endian(&val);

    push_u256!(state, val);
    Control::Continue(1 + n)
}

#[inline]
pub fn push0(state: &mut Machine) -> Control {
    push_u256!(state, U256_ZERO);
    Control::Continue(1)
}

#[inline]
pub fn push1(state: &mut Machine, position: usize) -> Control {
    let b0 = u64::from(*state.code.get(position + 1).unwrap_or(&0));
    let val = U256::from(b0);

    push_u256!(state, val);
    Control::Continue(2)
}

#[inline]
pub fn push2(state: &mut Machine, position: usize) -> Control {
    let b0 = u64::from(*state.code.get(position + 1).unwrap_or(&0));
    let b1 = u64::from(*state.code.get(position + 2).unwrap_or(&0));
    let val = U256::from((b0 << 8) | b1);

    push_u256!(state, val);
    Control::Continue(3)
}

#[inline]
pub fn dup(state: &mut Machine, n: usize) -> Control {
    let value = match state.stack.peek(n - 1) {
        Ok(value) => value,
        Err(e) => return Control::Exit(e.into()),
    };
    push_u256!(state, value);
    Control::Continue(1)
}

#[inline]
pub fn swap(state: &mut Machine, n: usize) -> Control {
    let val1 = match state.stack.peek(0) {
        Ok(value) => value,
        Err(e) => return Control::Exit(e.into()),
    };
    let val2 = match state.stack.peek(n) {
        Ok(value) => value,
        Err(e) => return Control::Exit(e.into()),
    };
    match state.stack.set(0, val2) {
        Ok(()) => (),
        Err(e) => return Control::Exit(e.into()),
    }
    match state.stack.set(n, val1) {
        Ok(()) => (),
        Err(e) => return Control::Exit(e.into()),
    }
    Control::Continue(1)
}

#[inline]
pub fn ret(state: &mut Machine) -> Control {
    pop_u256!(state, start, len);
    if len > U256_ZERO {
        let start = as_usize_or_fail!(start);
        let len = as_usize_or_fail!(len);
        try_or_fail!(state.memory.resize_offset(start, len));
    }
    state.return_range = start..(start + len);
    Control::Exit(ExitSucceed::Returned.into())
}

#[inline]
pub fn revert(state: &mut Machine) -> Control {
    pop_u256!(state, start, len);
    if len > U256_ZERO {
        let start = as_usize_or_fail!(start);
        let len = as_usize_or_fail!(len);
        try_or_fail!(state.memory.resize_offset(start, len));
    }
    state.return_range = start..(start + len);
    Control::Exit(ExitRevert::Reverted.into())
}
