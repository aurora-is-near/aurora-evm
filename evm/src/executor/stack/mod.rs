//! A stack-based executor with customizable state.
//! A memory-based state is provided, but can be replaced by a custom
//! implementation, for example one interacting with a database.

mod executor;
mod memory;
mod precompile;
mod tagged_runtime;

pub use self::executor::{
    Accessed, Authorization, StackExecutor, StackExitKind, StackState, StackSubstateMetadata,
};
pub use self::memory::{MemoryStackAccount, MemoryStackState, MemoryStackSubstate};
pub use self::precompile::{
    PrecompileFailure, PrecompileFn, PrecompileHandle, PrecompileOutput, PrecompileSet,
};
