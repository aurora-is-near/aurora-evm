use crate::types::blob::BlobExcessGasAndPrice;
use crate::types::json_utils::{
    deserialize_bytes_from_str_opt, deserialize_h160_from_str, deserialize_h160_from_str_opt,
    deserialize_h256_from_u256_str_opt, deserialize_u256_from_str, deserialize_u256_from_str_opt,
    deserialize_u8_from_str_opt, deserialize_vec_of_hex, deserialize_vec_u256_from_str,
};
use crate::types::{eip_4844, eip_7623, eip_7702, InvalidTxReason, PostState, Spec};
use aurora_evm::backend::MemoryVicinity;
use aurora_evm::executor::stack::Authorization;
use aurora_evm::gasometer;
use aurora_evm::gasometer::Gasometer;
use primitive_types::{H160, H256, U256};
use serde::Deserialize;
use sha3::Digest;

/// Transaction data.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(
        default,
        rename = "type",
        deserialize_with = "deserialize_u8_from_str_opt"
    )]
    pub tx_type: Option<u8>,
    #[serde(deserialize_with = "deserialize_vec_of_hex")]
    pub data: Vec<Vec<u8>>,
    #[serde(deserialize_with = "deserialize_vec_u256_from_str")]
    pub gas_limit: Vec<U256>,
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub gas_price: Option<U256>,
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub nonce: U256,
    #[serde(default, deserialize_with = "deserialize_h256_from_u256_str_opt")]
    pub secret_key: Option<H256>,
    #[serde(default, deserialize_with = "deserialize_h160_from_str_opt")]
    pub sender: Option<H160>,
    #[serde(default, deserialize_with = "deserialize_h160_from_str_opt")]
    pub to: Option<H160>,
    #[serde(deserialize_with = "deserialize_vec_u256_from_str")]
    pub value: Vec<U256>,
    /// for details on `maxFeePerGas` see EIP-1559
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub max_fee_per_gas: Option<U256>,
    /// for details on `maxPriorityFeePerGas` see EIP-1559
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(
        default,
        rename = "initcodes",
        deserialize_with = "deserialize_bytes_from_str_opt"
    )]
    pub init_codes: Option<Vec<u8>>,

    /// EIP-2930
    #[serde(default)]
    pub access_lists: Vec<Option<AccessList>>,

    /// EIP-4844
    #[serde(default, deserialize_with = "deserialize_vec_u256_from_str")]
    pub blob_versioned_hashes: Vec<U256>,
    /// EIP-4844
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub max_fee_per_blob_gas: Option<U256>,
    /// EIP-7702
    #[serde(default)]
    pub authorization_list: Option<AuthorizationList>,
}

impl Transaction {
    /// Get `data` from with state data
    #[must_use]
    pub fn get_data(&self, state: &PostState) -> Vec<u8> {
        self.data[state.indexes.data].clone()
    }

    /// Get `gas_limit` from with state data
    #[must_use]
    pub fn get_gas_limit(&self, state: &PostState) -> U256 {
        self.gas_limit[state.indexes.gas]
    }

    /// Get `value` from with state data
    #[must_use]
    pub fn get_value(&self, state: &PostState) -> U256 {
        self.value[state.indexes.value]
    }

    /// Get `access_list` from with state data
    #[must_use]
    pub fn get_access_list(&self, state: &PostState) -> Vec<(H160, Vec<H256>)> {
        if state.indexes.data < self.access_lists.len() {
            self.access_lists
                .get(state.indexes.data)
                .unwrap()
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|a| (a.address, a.storage_keys))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get caller from transaction's secret key.
    ///
    /// # Panics
    /// If the transaction secret is missing or if parsing the secret key fails.
    #[must_use]
    pub fn get_caller_from_secret_key(&self) -> H160 {
        let hash = self.secret_key.unwrap();
        let mut secret_key = [0; 32];
        secret_key.copy_from_slice(hash.as_bytes());
        let secret = libsecp256k1::SecretKey::parse(&secret_key);
        let public = libsecp256k1::PublicKey::from_secret_key(&secret.unwrap());
        let mut res = [0u8; 64];
        res.copy_from_slice(&public.serialize()[1..65]);

        H160::from(H256::from_slice(
            <[u8; 32]>::from(sha3::Keccak256::digest(res)).as_slice(),
        ))
    }

    fn intrinsic_gas(&self, config: &aurora_evm::Config, state: &PostState) -> Option<u64> {
        let is_contract_creation = self.to.is_none();
        let data = &self.get_data(state);
        let access_list = self.get_access_list(state);

        // EIP-7702
        let authorization_list_len = self.authorization_list.as_ref().map_or(0, Vec::len);

        let cost = if is_contract_creation {
            gasometer::create_transaction_cost(data, &access_list)
        } else {
            gasometer::call_transaction_cost(data, &access_list, authorization_list_len)
        };

        let mut g = Gasometer::new(u64::MAX, config);
        g.record_transaction(cost).ok()?;

        Some(g.total_used_gas())
    }

    /// Validate the transaction against block, payment, and EIP constraints.
    ///
    /// # Errors
    /// Returns `InvalidTxReason` if validation fails.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub fn validate(
        &self,
        block_gas_limit: U256,
        caller_balance: U256,
        config: &aurora_evm::Config,
        vicinity: &MemoryVicinity,
        blob_gas_price: Option<BlobExcessGasAndPrice>,
        data_fee: Option<U256>,
        spec: &Spec,
        state: &PostState,
    ) -> Result<Vec<Authorization>, InvalidTxReason> {
        let gas_limit = self.get_gas_limit(state);
        let mut authorization_list: Vec<Authorization> = vec![];
        match self.intrinsic_gas(config, state) {
            None => return Err(InvalidTxReason::IntrinsicGas),
            Some(required_gas) => {
                if gas_limit < U256::from(required_gas) {
                    return Err(InvalidTxReason::IntrinsicGas);
                }
            }
        }

        if block_gas_limit < gas_limit {
            return Err(InvalidTxReason::GasLimitReached);
        }

        let required_funds = gas_limit
            .checked_mul(vicinity.gas_price)
            .ok_or(InvalidTxReason::OutOfFund)?
            .checked_add(self.get_value(state))
            .ok_or(InvalidTxReason::OutOfFund)?;

        let required_funds = if let Some(data_fee) = data_fee {
            required_funds
                .checked_add(data_fee)
                .ok_or(InvalidTxReason::OutOfFund)?
        } else {
            required_funds
        };
        if caller_balance < required_funds {
            return Err(InvalidTxReason::OutOfFund);
        }

        // CANCUN tx validation
        // Presence of max_fee_per_blob_gas means that this is a blob transaction.
        if *spec >= Spec::Cancun {
            if let Some(max) = self.max_fee_per_blob_gas {
                // ensure that the user was willing to at least pay the current blob gasprice
                if U256::from(
                    blob_gas_price
                        .expect("expect blob_gas_price")
                        .blob_gas_price,
                ) > max
                {
                    return Err(InvalidTxReason::BlobGasPriceGreaterThanMax);
                }

                // there must be at least one blob
                if self.blob_versioned_hashes.is_empty() {
                    return Err(InvalidTxReason::EmptyBlobs);
                }

                // The field `to` deviates slightly from the semantics with the exception
                // that it MUST NOT be nil and therefore must always represent
                // a 20-byte address. This means that blob transactions cannot
                // have the form of a `create` transaction.
                if self.to.is_none() {
                    return Err(InvalidTxReason::BlobCreateTransaction);
                }

                // all versioned blob hashes must start with VERSIONED_HASH_VERSION_KZG
                for blob in &self.blob_versioned_hashes {
                    let blob_hash = H256(blob.to_big_endian());
                    if blob_hash[0] != eip_4844::VERSIONED_HASH_VERSION_KZG {
                        return Err(InvalidTxReason::BlobVersionNotSupported);
                    }
                }

                // ensure the total blob gas spent is at most equal to the limit
                // assert blob_gas_used <= MAX_BLOB_GAS_PER_BLOCK
                // EIP-7691
                let max_blob_len = if *spec == Spec::Cancun {
                    eip_4844::MAX_BLOBS_PER_BLOCK_CANCUN
                } else {
                    eip_4844::MAX_BLOBS_PER_BLOCK_ELECTRA
                };
                if self.blob_versioned_hashes.len() > usize::try_from(max_blob_len).unwrap() {
                    return Err(InvalidTxReason::TooManyBlobs);
                }
            }
        } else {
            if !self.blob_versioned_hashes.is_empty() {
                return Err(InvalidTxReason::BlobVersionedHashesNotSupported);
            }
            if self.max_fee_per_blob_gas.is_some() {
                return Err(InvalidTxReason::MaxFeePerBlobGasNotSupported);
            }
        }

        if *spec >= Spec::Prague {
            // EIP-7623 validation
            let floor_gas = eip_7623::calc_tx_floor_cost(eip_7623::get_tokens_in_calldata(
                &self.get_data(state),
            ));
            if floor_gas > gas_limit.as_u64() {
                return Err(InvalidTxReason::GasFloorMoreThanGasLimit);
            }

            let tx_authorization_list = self.authorization_list.clone().unwrap_or_default();

            // EIP-7702 - if transaction type is EOAAccountCode then
            // `authorization_list` must be present
            if TxType::from_tx_bytes(&state.tx_bytes) == TxType::EOAAccountCode
                && tx_authorization_list.is_empty()
            {
                return Err(InvalidTxReason::AuthorizationListNotExist);
            }

            // Check EIP-7702 Spec validation steps: 1 and 2
            // Other validation step inside EVM transact logic.
            for auth in &tx_authorization_list {
                // 1. Verify the chain id is either 0 or the chain’s current ID.
                let mut is_valid = auth.chain_id <= U256::from(u64::MAX)
                    && (auth.chain_id == U256::from(0) || auth.chain_id == vicinity.chain_id);

                // 3. `authority = ecrecover(keccak(MAGIC || rlp([chain_id, address, nonce])), y_parity, r, s]`
                // Validate the signature, as in tests it is possible to have invalid signatures values.
                // Value `v` shouldn't be greater then 1
                let v = auth.v;
                if v > U256::from(1) {
                    is_valid = false;
                }

                // EIP-2 validation
                if auth.s > eip_7702::SECP256K1N_HALF {
                    is_valid = false;
                }

                let auth_address = eip_7702::SignedAuthorization::new(
                    auth.chain_id,
                    auth.address,
                    auth.nonce.as_u64(),
                    auth.r,
                    auth.s,
                    auth.v.as_u32() > 0,
                )
                .recover_address();
                let auth_address = auth_address.unwrap_or_else(|_| {
                    is_valid = false;
                    H160::zero()
                });

                authorization_list.push(Authorization {
                    authority: auth_address,
                    address: auth.address,
                    nonce: auth.nonce.as_u64(),
                    is_valid,
                });
            }
        } else if self.authorization_list.is_some() {
            return Err(InvalidTxReason::AuthorizationListNotSupported);
        }
        Ok(authorization_list)
    }
}

/// Type alias for access lists (see EIP-2930)
pub type AccessList = Vec<AccessListTuple>;

/// Access list tuple (see <https://eips.ethereum.org/EIPS/eip-2930>).
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListTuple {
    /// Address to access
    #[serde(deserialize_with = "deserialize_h160_from_str")]
    pub address: H160,
    /// Keys (slots) to access at that address
    pub storage_keys: Vec<H256>,
}

/// EIP-7702 Authorization List
pub type AuthorizationList = Vec<AuthorizationItem>;
/// EIP-7702 Authorization item
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationItem {
    /// Chain ID
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub chain_id: U256,
    /// Address to access
    #[serde(deserialize_with = "deserialize_h160_from_str")]
    pub address: H160,
    /// Keys (slots) to access at that address
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub nonce: U256,
    /// r signature
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub r: U256,
    /// s signature
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub s: U256,
    /// Parity
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub v: U256,
    /// Signer address
    #[serde(default, deserialize_with = "deserialize_h160_from_str_opt")]
    pub signer: Option<H160>,
}

/// Denotes the type of transaction.
#[derive(Debug, PartialEq, Eq)]
pub enum TxType {
    /// All transactions before EIP-2718 are legacy.
    Legacy,
    /// <https://eips.ethereum.org/EIPS/eip-2718>
    AccessList,
    /// <https://eips.ethereum.org/EIPS/eip-1559>
    DynamicFee,
    /// <https://eips.ethereum.org/EIPS/eip-4844>
    ShardBlob,
    /// <https://eips.ethereum.org/EIPS/eip-7702>
    EOAAccountCode,
}

impl TxType {
    /// Whether this is a legacy, access list, dynamic fee, etc. transaction
    /// Taken from geth's core/types/transaction.go/UnmarshalBinary, but we only detect the transaction
    /// type rather than unmarshal the entire payload.
    #[must_use]
    pub const fn from_tx_bytes(tx_bytes: &[u8]) -> Self {
        match tx_bytes[0] {
            b if b > 0x7f => Self::Legacy,
            1 => Self::AccessList,
            2 => Self::DynamicFee,
            3 => Self::ShardBlob,
            4 => Self::EOAAccountCode,
            _ => panic!(
                "Unknown tx type. You may need to update the TxType enum if Ethereum introduced new enveloped transaction types."
            ),
        }
    }
}
