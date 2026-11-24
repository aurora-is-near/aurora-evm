//! Journal metadata must not prevent downstream users from constructing an account literal.

use aurora_evm::backend::Basic;
use aurora_evm::executor::stack::MemoryStackAccount;

#[test]
fn memory_stack_account_supports_public_struct_literals() {
    let _ = MemoryStackAccount {
        basic: Basic::default(),
        code: None,
        reset: false,
    };
}
