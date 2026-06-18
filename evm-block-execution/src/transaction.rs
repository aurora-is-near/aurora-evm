use aurora_evm::executor::stack::Authorization;
use primitive_types::{H160, U256};

use crate::evm_context::EvmContext;
pub use access_list::{AccessList, AccessListItem};
pub use tx_kind::TxKind;
pub use tx_type::TxType;

mod access_list;
pub mod eip7825;
mod tx_kind;
mod tx_type;

/// The Transaction Environment is a struct that contains all fields
/// that can be found in all Ethereum transaction,  including:
/// EIP-4844, EIP-7702, EIP-7873, etc.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// Returns the transaction type.
    pub tx_type: TxType,

    /// The destination of the transaction
    pub tx_kind: TxKind,

    /// Caller aka Author aka transaction signer.
    pub caller: H160,

    /// The maximum amount of gas the transaction can use.
    pub gas_limit: u64,

    /// The value sent to the receiver of [`TxKind::Call`].
    pub value: U256,

    /// The data of the transaction
    pub data: Vec<u8>,

    /// The nonce of the transaction.
    ///
    /// Note : Common field for all transactions.
    pub nonce: U256,

    /// The chain ID of the transaction
    ///
    /// Incorporated as part of the Spurious Dragon upgrade via [EIP-155].
    ///
    /// [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
    pub chain_id: Option<u64>,

    /// Gas price for the transaction.
    /// Available for legacy transactions, optional for EIP-1559 transactions.
    /// Only before EIP-1559 - London hard fork.
    pub gas_price: Option<U256>,

    /// Maximum fee that can be paid for the transaction.
    /// Available only from EIP-1559 transactions.
    pub max_fee_per_gas: Option<U256>,

    /// Maximum priority fee per gas.
    /// Available only from EIP-1559 transactions.
    pub max_priority_fee_per_gas: Option<U256>,

    /// Access list for the transaction.
    ///
    /// Introduced in EIP-2930.
    pub access_list: AccessList,

    /// Returns vector of fixed size hash(32 bytes)
    /// EIP-4844 transaction field.
    pub blob_versioned_hashes: Vec<U256>,

    /// Max fee per data gas
    /// EIP-4844 transaction field.
    pub max_fee_per_blob_gas: u128,

    /// List of authorizations, that contains the signature that authorizes this
    /// caller to place the code to signer account.
    ///
    /// Set EOA account code for one transaction
    ///
    /// [EIP-Set EOA account code for one transaction](https://eips.ethereum.org/EIPS/eip-7702)
    pub authorization_list: Vec<Authorization>,
}

impl Transaction {
    #[must_use]
    pub fn validate(&self, _ctx: &EvmContext) -> bool {
        todo!()
    }

    pub fn calculate_initial_tx_gas_for_tx(&self) {
        todo!()
    }
}
