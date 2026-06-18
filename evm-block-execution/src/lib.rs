#![deny(warnings)]
#![deny(clippy::pedantic, clippy::nursery)]
#![deny(clippy::as_conversions)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod blob;
pub mod block;
pub mod errors;
pub mod evm;
pub mod evm_context;
pub mod spec;
pub mod transaction;
