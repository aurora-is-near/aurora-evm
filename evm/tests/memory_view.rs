//! A trace snapshot covers MSIZE without materializing zeroes in the execution buffer.

use std::{borrow::Cow, rc::Rc};

use aurora_evm::{Capture, ExitError, ExitReason, InterpreterHandler, Machine, Memory, Opcode};
use primitive_types::{H160, U256};

struct NoGas;

impl InterpreterHandler for NoGas {
    fn before_bytecode(
        &mut self,
        _: Opcode,
        _: usize,
        _: &Machine,
        _: &H160,
    ) -> Result<(), ExitError> {
        Ok(())
    }

    #[cfg(feature = "tracing")]
    fn after_bytecode(
        &mut self,
        _: &Result<(), Capture<ExitReason, aurora_evm::Trap>>,
        _: &Machine,
    ) {
    }
}

#[test]
fn mstore8_snapshot_matches_msize_without_growing_the_buffer() {
    let mut machine = Machine::new(
        Rc::new(vec![0x60, 0xab, 0x60, 0, 0x53, 0x59, 0x00]),
        Rc::new(Vec::new()),
        1024,
        usize::MAX,
    );
    let mut handler = NoGas;

    assert!(matches!(
        machine.step(&mut handler, &H160::zero()),
        Err(Capture::Exit(ExitReason::Succeed(_)))
    ));
    assert_eq!(machine.stack().data(), &[U256::from(32)]);

    let memory = machine.memory();

    assert_eq!(memory.data(), &[0xab]);

    let capacity = memory.data().capacity();
    let snapshot = memory.effective_data();

    assert!(matches!(snapshot, Cow::Owned(_)));
    assert_eq!(snapshot.len(), 32);
    assert_eq!(snapshot[0], 0xab);
    assert_eq!(&snapshot[1..], &[0; 31]);
    assert_eq!(memory.data().capacity(), capacity);
    assert_eq!(memory.len(), 1);
    assert_eq!(memory.effective_len(), 32);
    assert!(matches!(
        machine.step(&mut handler, &H160::zero()),
        Err(Capture::Exit(ExitReason::Succeed(_)))
    ));
}

#[test]
fn unwritten_effective_memory_is_zero_padded() {
    let mut memory = Memory::new(usize::MAX);
    memory.resize_offset(31, 2).unwrap();

    assert!(memory.is_empty());
    assert_eq!(memory.effective_len(), 64);
    assert_eq!(memory.effective_data().as_ref(), &[0; 64]);
    assert_eq!(memory.get(32, 32), vec![0; 32]);
    assert_eq!(memory.data().capacity(), 0);
}

#[test]
fn materialized_and_empty_snapshots_borrow_storage() {
    let mut memory = Memory::new(usize::MAX);

    assert!(matches!(memory.effective_data(), Cow::Borrowed([])));

    memory.resize_end(32).unwrap();
    memory.set(0, &[0xab; 32], 32).unwrap();
    let snapshot = memory.effective_data();

    assert!(matches!(snapshot, Cow::Borrowed(_)));
    assert_eq!(snapshot.as_ptr(), memory.data().as_ptr());
    assert_eq!(snapshot.as_ref(), &[0xab; 32]);
}

#[test]
fn snapshot_does_not_expose_writes_outside_effective_memory() {
    // Direct host writes do not run the interpreter's expansion step.
    let mut memory = Memory::new(usize::MAX);
    memory.set(0, &[1; 64], 64).unwrap();

    assert!(memory.effective_data().is_empty());

    memory.resize_end(32).unwrap();

    assert_eq!(memory.effective_data().as_ref(), &[1; 32]);
    assert_eq!(memory.len(), 64);
}

#[test]
fn padded_snapshot_is_independent_of_later_writes() {
    let mut memory = Memory::new(usize::MAX);
    memory.resize_end(32).unwrap();
    memory.set(0, &[7], 1).unwrap();
    let snapshot = memory.effective_data().into_owned();
    memory.set(0, &[8], 1).unwrap();

    assert_eq!(snapshot[0], 7);
    assert_eq!(memory.effective_data()[0], 8);
}
