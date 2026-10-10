//! Transactions, in the two shapes this crate needs them.
//!
//! **The consensus shape** is [`SignedTxEnvelope`] — a sum over the transaction types, each holding
//! exactly its own fields. It is what a block body carries, what the RLP is made of, and what the two
//! hashes are computed from. It cannot describe a transaction that contradicts its own type.
//!
//! **The execution shape** is [`TxEnv`] — the union of every type's fields, which is what an
//! interpreter wants to read. It is derived from the consensus shape and never the other way round.
//!
//! Everything else here is a part shared by both: the destination ([`TxKind`]), the type tag
//! ([`TxType`]), the signature ([`TxSignature`]), an access list ([`AccessList`]) and an EIP-7702
//! authorization tuple ([`SignedAuthorization`]).

pub use access_list::{AccessList, AccessListItem};
pub use env::TxEnv;
pub use signature::{SECP256K1N_HALF, TxSignature};
pub use signed_authorization::SignedAuthorization;
pub use tx_kind::TxKind;
pub use tx_type::TxType;
pub use types::{
    SignedTxEip1559, SignedTxEip2930, SignedTxEip4844, SignedTxEip7702, SignedTxEnvelope,
    SignedTxLegacy, TxDecodeError, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy,
};

mod access_list;
mod env;
mod signature;
mod signed_authorization;
mod tx_kind;
mod tx_type;
pub mod types;
