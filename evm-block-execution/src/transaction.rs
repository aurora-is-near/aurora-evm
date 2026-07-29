use aurora_evm::executor::stack::Authorization;
use core::ops::Deref;
use primitive_types::H160;

pub use access_list::{AccessList, AccessListItem};
pub use encode::TxEncodeError;
pub use payload::TxPayload;
pub use signature::{SECP256K1N_HALF, TxSignature};
pub use signed::{SignedTransaction, TxDecodeError};
pub use signed_authorization::SignedAuthorization;
pub use tx_kind::TxKind;
pub use tx_type::TxType;

mod access_list;
pub mod eip7825;
mod encode;
mod payload;
mod signature;
mod signed;
mod signed_authorization;
mod tx_kind;
mod tx_type;

/// A transaction ready to execute: its signed fields, its sender, and its recovered
/// authorizations.
///
/// This is the *execution* form. It carries no signature: the sender has already been established
/// by verifying one, and the EIP-7702 authorizations it holds are the recovered authorities rather
/// than the signed tuples they came from. The consensus form those two are derived from is
/// [`SignedTransaction`].
///
/// The signed fields live in [`TxPayload`], which both forms share, so the consensus field set is
/// defined in one place. They are readable directly on the transaction (`tx.gas_limit`) through
/// [`Deref`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// The fields the sender signed.
    pub payload: TxPayload,

    /// Caller aka Sender aka transaction signer.
    pub caller: H160,

    /// Authorizations that let this caller set code on the signing accounts, with each authority
    /// already recovered.
    ///
    /// Set EOA account code for one transaction
    ///
    /// [EIP-Set EOA account code for one transaction](https://eips.ethereum.org/EIPS/eip-7702)
    pub authorization_list: Vec<Authorization>,
}

impl Deref for Transaction {
    type Target = TxPayload;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}
