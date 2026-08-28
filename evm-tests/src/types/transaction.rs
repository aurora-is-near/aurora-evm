use crate::types::blob::BlobExcessGasAndPrice;
use crate::types::json_utils::{
    deserialize_bytes_from_str_opt, deserialize_h160_from_str, deserialize_h160_from_str_opt,
    deserialize_h256_from_u256_str_opt, deserialize_u8_from_str_opt, deserialize_u128_from_str_opt,
    deserialize_u256_from_str, deserialize_u256_from_str_opt, deserialize_vec_of_hex,
    deserialize_vec_u256_from_str,
};
use crate::types::{InvalidTxReason, PostState, Spec, eip_4844, eip_7702};
use aurora_evm::backend::MemoryVicinity;
use aurora_evm::executor::stack::Authorization;
use aurora_evm::gasometer::Gasometer;
use primitive_types::{H160, H256, U256};
use serde::Deserialize;
use sha3::Digest;

/// EIP-7825: maximum transaction gas limit starting from Osaka (2^24).
const MAX_TX_GAS_LIMIT_OSAKA: u64 = 1 << 24;

/// The order of the secp256k1 curve.
const SECP256K1N: U256 = U256([
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
]);

/// Signature of a signed transaction: the chain id it is signed for (`None` for pre-EIP-155
/// legacy transactions), `v` (`y_parity` for typed ones), `r` and `s`.
struct TxSignature {
    chain_id: Option<U256>,
    v: U256,
    r: U256,
    s: U256,
    signing_hash: [u8; 32],
}

impl TxSignature {
    /// Parses the signature fields from the RLP of a signed transaction.
    fn parse(tx_bytes: &[u8]) -> Option<Self> {
        let prefix = *tx_bytes.first()?;
        let tx_type = TxType::from_tx_bytes(tx_bytes);
        let payload = if tx_type == TxType::Legacy {
            tx_bytes
        } else {
            tx_bytes.get(1..)?
        };

        let mut rlp = rlp::Rlp::new(payload);
        // EIP-4844 network form wraps the transaction together with blobs
        if tx_type == TxType::ShardBlob && rlp.at(0).ok()?.is_list() {
            rlp = rlp.at(0).ok()?;
        }

        let count = rlp.item_count().ok()?;
        let expected_count = match tx_type {
            TxType::Legacy => 9,
            TxType::AccessList => 11,
            TxType::DynamicFee => 12,
            TxType::ShardBlob => 14,
            TxType::EOAAccountCode => 13,
        };
        if count != expected_count {
            return None;
        }
        let value = |index| rlp.val_at::<U256>(index).ok();

        let v = value(count - 3)?;
        let chain_id = if tx_type == TxType::Legacy {
            // EIP-155: `v = chain_id * 2 + 35/36`; pre-EIP-155 `27/28` carry no chain id
            (v >= U256::from(35)).then(|| (v - U256::from(35)) / U256::from(2))
        } else {
            Some(value(0)?)
        };

        // The signature covers all payload fields except v/r/s. Protected legacy transactions
        // append the EIP-155 chain id and two zeroes; typed transactions include the type byte.
        let protected_legacy = tx_type == TxType::Legacy && chain_id.is_some();
        let signing_count = if protected_legacy { count } else { count - 3 };
        let mut signing_payload = rlp::RlpStream::new_list(signing_count);
        for index in 0..count - 3 {
            signing_payload.append_raw(rlp.at(index).ok()?.as_raw(), 1);
        }

        if protected_legacy {
            signing_payload.append(&chain_id?).append(&0u8).append(&0u8);
        }

        let mut hasher = sha3::Keccak256::new();
        if tx_type != TxType::Legacy {
            hasher.update([prefix]);
        }

        hasher.update(signing_payload.as_raw());

        Some(Self {
            chain_id,
            v,
            r: value(count - 2)?,
            s: value(count - 1)?,
            signing_hash: hasher.finalize().into(),
        })
    }

    /// Enforces signature ranges and EIP-2, then recovers the public key from the signing hash.
    /// Recovery rejects both an r without a curve point and a resulting key at infinity.
    fn recover_public_key(&self, legacy: bool) -> Option<libsecp256k1::PublicKey> {
        let parity = if !legacy {
            self.v
        } else if self.v == U256::from(27) || self.v == U256::from(28) {
            self.v - U256::from(27)
        } else if self.v >= U256::from(35) {
            (self.v - U256::from(35)) % U256::from(2)
        } else {
            return None;
        };

        if parity > U256::one()
            || self.r.is_zero()
            || self.r >= SECP256K1N
            || self.s.is_zero()
            || self.s > eip_7702::SECP256K1N_HALF
        {
            return None;
        }
        let recovery_id = libsecp256k1::RecoveryId::parse(u8::from(parity == U256::one())).ok()?;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r.to_big_endian());
        bytes[32..].copy_from_slice(&self.s.to_big_endian());
        let signature = libsecp256k1::Signature::parse_standard(&bytes).ok()?;
        let message = libsecp256k1::Message::parse(&self.signing_hash);
        libsecp256k1::recover(&message, &signature, &recovery_id).ok()
    }
}

/// Ethereum address of a public key: the last 20 bytes of the keccak256 of its uncompressed form.
fn public_key_address(public_key: &libsecp256k1::PublicKey) -> H160 {
    let hash = sha3::Keccak256::digest(&public_key.serialize()[1..]);
    H160::from_slice(&hash[12..])
}

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
    /// Transaction chain ID (absent in legacy fixtures)
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub chain_id: Option<U256>,
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
    #[serde(default, deserialize_with = "deserialize_u128_from_str_opt")]
    pub max_fee_per_blob_gas: Option<u128>,
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

    /// Get `access_list` for the current state data index (empty if absent or out of range).
    #[must_use]
    pub fn get_access_list(&self, state: &PostState) -> Vec<(H160, Vec<H256>)> {
        self.access_lists
            .get(state.indexes.data)
            .cloned()
            .flatten()
            .unwrap_or_default()
            .into_iter()
            .map(|a| (a.address, a.storage_keys))
            .collect()
    }

    /// Get caller from transaction's secret key, or from `sender` when the fixture has no key
    /// (transactions with an invalid signature can't be signed by the filler).
    ///
    /// # Panics
    /// If both the secret key and the sender are missing, or if parsing the secret key fails.
    #[must_use]
    pub fn get_caller_from_secret_key(&self) -> H160 {
        let Some(hash) = self.secret_key else {
            return self
                .sender
                .expect("expect transaction secret key or sender");
        };
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

    fn intrinsic_gas_and_gas_floor(
        &self,
        config: &aurora_evm::Config,
        state: &PostState,
    ) -> (u64, u64) {
        let is_contract_creation = self.to.is_none();
        let data = &self.get_data(state);
        let access_list = self.get_access_list(state);
        // EIP-7702
        let authorization_list_len = self.authorization_list.as_ref().map_or(0, Vec::len);

        Gasometer::calculate_intrinsic_gas_and_gas_floor(
            data,
            &access_list,
            authorization_list_len,
            config,
            is_contract_creation,
        )
    }

    /// Validate the transaction against block, payment, and EIP constraints.
    ///
    /// # Errors
    /// Returns `InvalidTxReason` if validation fails.
    ///
    /// ## Panics
    /// Panics if a blob (EIP-4844) transaction is validated without a `blob_gas_price`.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub fn validate(
        &self,
        block_gas_limit: U256,
        caller_balance: U256,
        caller_nonce: U256,
        config: &aurora_evm::Config,
        vicinity: &MemoryVicinity,
        blob_gas_price: Option<BlobExcessGasAndPrice>,
        data_fee: Option<U256>,
        spec: &Spec,
        state: &PostState,
    ) -> Result<Vec<Authorization>, InvalidTxReason> {
        let gas_limit = self.get_gas_limit(state);
        let mut authorization_list: Vec<Authorization> = vec![];

        // The sender is defined only by a valid signature for the expected chain
        let Some(signature) = TxSignature::parse(&state.tx_bytes) else {
            return Err(InvalidTxReason::InvalidSignature);
        };
        let Some(public_key) =
            signature.recover_public_key(TxType::from_tx_bytes(&state.tx_bytes) == TxType::Legacy)
        else {
            return Err(InvalidTxReason::InvalidSignature);
        };
        // The signature must belong to the sender the fixture executes the transaction with
        if public_key_address(&public_key) != vicinity.origin {
            return Err(InvalidTxReason::InvalidSignature);
        }

        // The signed chain id (protected legacy and typed transactions) and the fixture field,
        // when present, must both be the chain of the test
        let wrong_chain = |chain_id: U256| chain_id != vicinity.chain_id;
        if signature.chain_id.is_some_and(wrong_chain) || self.chain_id.is_some_and(wrong_chain) {
            return Err(InvalidTxReason::InvalidChainId);
        }

        // EIP-2681: transaction nonce must be below 2^64-1, then it must match the sender nonce
        if self.nonce >= U256::from(u64::MAX) {
            return Err(InvalidTxReason::NonceIsMax);
        }

        if self.nonce > caller_nonce {
            return Err(InvalidTxReason::NonceTooHigh);
        }

        if self.nonce < caller_nonce {
            return Err(InvalidTxReason::NonceTooLow);
        }

        // EIP-7825: the cap is checked before any other gas validation
        if *spec >= Spec::Osaka && gas_limit > U256::from(MAX_TX_GAS_LIMIT_OSAKA) {
            return Err(InvalidTxReason::GasLimitExceedsMaximum);
        }

        let (intrinsic_gas, floor_gas) = self.intrinsic_gas_and_gas_floor(config, state);
        if gas_limit < U256::from(intrinsic_gas) {
            return Err(InvalidTxReason::IntrinsicGas);
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

        if TxType::from_tx_bytes(&state.tx_bytes) == TxType::AccessList && *spec < Spec::Berlin {
            return Err(InvalidTxReason::AccessListNotSupported);
        }

        // CANCUN tx validation
        // Presence of max_fee_per_blob_gas means that this is a blob transaction.
        if *spec >= Spec::Cancun {
            if let Some(max) = self.max_fee_per_blob_gas {
                // ensure that the user was willing to at least pay the current blob gasprice
                if blob_gas_price
                    .expect("expect blob_gas_price")
                    .blob_gas_price
                    > max
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

                // EIP-7594: per-transaction blob limit starting from Osaka
                if *spec >= Spec::Osaka
                    && self.blob_versioned_hashes.len()
                        > usize::try_from(eip_4844::MAX_BLOBS_PER_TX_OSAKA).unwrap()
                {
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

            // EIP-7702 - if transaction is contract creation - validation fails
            if TxType::from_tx_bytes(&state.tx_bytes) == TxType::EOAAccountCode && self.to.is_none()
            {
                return Err(InvalidTxReason::AuthorizationListNotSupportedForCreate);
            }

            // Apply EIP-7702 steps 1 and 3. Aurora EVM applies step 2 and steps 4-9 after
            // incrementing the transaction sender's nonce.
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
    ///
    /// ## Panics
    /// Panics if `tx_bytes` is empty, or if its first byte is an unknown enveloped transaction type.
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

#[cfg(test)]
mod signature_tests {
    use super::*;
    use rlp::RlpStream;

    /// x-coordinate of the secp256k1 generator; `5` has no curve point
    const CURVE_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn legacy(v: u64, r: U256, s: U256) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        for _ in 0..6 {
            stream.append(&0u8);
        }
        stream.append(&v).append(&r).append(&s);
        stream.out().to_vec()
    }

    fn typed(tx_type: u8, chain_id: U256, y_parity: u8, r: U256, s: U256) -> Vec<u8> {
        let count = match tx_type {
            1 => 11,
            2 => 12,
            3 => 14,
            4 => 13,
            _ => unreachable!(),
        };
        let mut stream = RlpStream::new_list(count);
        stream.append(&chain_id);
        for _ in 1..count - 3 {
            stream.append(&0u8);
        }
        stream.append(&y_parity).append(&r).append(&s);
        let mut bytes = vec![tx_type];
        bytes.extend(stream.out());
        bytes
    }

    #[test]
    fn legacy_signature_chain_id_and_validity() {
        let r = U256::from_str_radix(CURVE_X, 16).unwrap();
        let signature = TxSignature::parse(&legacy(37, r, U256::one())).unwrap();
        assert_eq!(signature.chain_id, Some(U256::one()));
        assert!(signature.recover_public_key(true).is_some());
        assert_eq!(
            TxSignature::parse(&legacy(28, r, U256::one()))
                .unwrap()
                .chain_id,
            None
        );
        assert_eq!(
            TxSignature::parse(&legacy(2 * 1337 + 36, r, U256::one()))
                .unwrap()
                .chain_id,
            Some(U256::from(1337))
        );
        // `r` without a curve point, `s` above n/2 and a malformed `v` are invalid
        assert!(
            TxSignature::parse(&legacy(37, U256::from(5), U256::one()))
                .unwrap()
                .recover_public_key(true)
                .is_none()
        );
        assert!(
            TxSignature::parse(&legacy(37, r, SECP256K1N - U256::one()))
                .unwrap()
                .recover_public_key(true)
                .is_none()
        );
        assert!(
            TxSignature::parse(&legacy(34, r, U256::one()))
                .unwrap()
                .recover_public_key(true)
                .is_none()
        );
    }

    #[test]
    fn typed_signature_chain_id_and_validity() {
        let r = U256::from_str_radix(CURVE_X, 16).unwrap();
        let signature = TxSignature::parse(&typed(2, U256::from(2), 1, r, U256::one())).unwrap();
        assert_eq!(signature.chain_id, Some(U256::from(2)));
        assert!(signature.recover_public_key(false).is_some());
        assert!(
            TxSignature::parse(&typed(1, U256::one(), 2, r, U256::one()))
                .unwrap()
                .recover_public_key(false)
                .is_none()
        );
    }

    // ethereum/tests v17.0 rangesExample (unprotected legacy), followed by EEST tests@v20.0.2
    // invalid_chain_id (protected legacy and types 1-4). The latter signatures are valid on chain 2.
    const SIGNED_TRANSACTIONS: &[(&str, &str)] = &[
        (
            "f863800a83061a8094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a0011ca064f084caf7c68cc95d8d2681b780c9743198f0d751564bd2b6d090c140375e86a07d65260b3168acbdbf8d9bd3eea906fffe193e75d5a0ea6edd0689dafb2f3846",
            "a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        ),
        (
            "f861800a840100000094f89a03b42ea1412874da2cf1ae48956f73d06039018027a0b10bbb1ed080a26a866e80656874b633fbc34aa4a61e96434b387ca4be6ecce3a00b0700ce8087ed706466c9a5f65e9daf4781023a20bda97f3ea57953a74f96ad",
            "f6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff",
        ),
        (
            "01f86302800a840100000094f89a03b42ea1412874da2cf1ae48956f73d060390180c080a0ff85d50df3c32b3b0e622493c84cd1027c91ca684ed9844f83f82f66802aedfda04c5842ca3f95a084b950b86a7645696609a18dd1ec075e7ad0f25fd1beb119ba",
            "f6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff",
        ),
        (
            "02f86402808007840100000094f89a03b42ea1412874da2cf1ae48956f73d060390180c001a05403282ccd84522eaaac7e09597cd42623aa5154d42f2770cd4043c8307c71a6a01fb5041dd091818086d4e92e7adac0ab91c23684b38138fb17330574f4e70928",
            "f6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff",
        ),
        (
            "03f88702808007840100000094f89a03b42ea1412874da2cf1ae48956f73d060390180c001e1a0010000000000000000000000000000000000000000000000000000000000000080a0d582783cdf1d4f3e7eb547b6f2431585cc63a4ca3b2d4e78b935a0915603e738a014b88fa885b03afead6b672d7e64d838a0aeef158b9e949c897c6d9452e88114",
            "f6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff",
        ),
        (
            "04f86502808007840100000094f89a03b42ea1412874da2cf1ae48956f73d060390180c0c001a090abe3293b7fe840d0358e760fd4c61a8c006438cfdab7f1128c41311af488b2a05a2b3d61820cb18ea2292025f195d59a66c726bff56cc982c331bf48a181e25b",
            "f6c3a9edc1afa0ad5b720e4d42e1437c43d3b3ff",
        ),
    ];

    #[test]
    fn recovery_matches_reference_senders_for_every_envelope() {
        for (encoded, sender) in SIGNED_TRANSACTIONS {
            let bytes = hex::decode(encoded).unwrap();
            let legacy = TxType::from_tx_bytes(&bytes) == TxType::Legacy;
            let signature = TxSignature::parse(&bytes).unwrap();
            let key = signature.recover_public_key(legacy).unwrap();
            let hash = sha3::Keccak256::digest(&key.serialize()[1..]);
            assert_eq!(hex::encode(&hash[12..]), *sender);
        }
    }

    fn replace_signature(bytes: &[u8], v: U256, r: U256, s: U256) -> Vec<u8> {
        let legacy = TxType::from_tx_bytes(bytes) == TxType::Legacy;
        let payload = rlp::Rlp::new(if legacy { bytes } else { &bytes[1..] });
        let count = payload.item_count().unwrap();
        let mut stream = RlpStream::new_list(count);
        for index in 0..count - 3 {
            stream.append_raw(payload.at(index).unwrap().as_raw(), 1);
        }

        stream.append(&v).append(&r).append(&s);
        let mut result = Vec::new();
        if !legacy {
            result.push(bytes[0]);
        }

        result.extend(stream.out());
        result
    }

    #[test]
    fn recovery_rejects_infinity_for_every_envelope_and_checks_parity() {
        for (encoded, _) in SIGNED_TRANSACTIONS {
            let bytes = hex::decode(encoded).unwrap();
            let legacy = TxType::from_tx_bytes(&bytes) == TxType::Legacy;
            let signature = TxSignature::parse(&bytes).unwrap();
            // Construct R = zG and s = 1. Both scalars and R are valid, but recovery produces
            // Q = r^-1 * (sR - zG) = infinity. This does not require finding a hash preimage.
            let scalar = libsecp256k1::SecretKey::parse(&signature.signing_hash).unwrap();
            let point = libsecp256k1::PublicKey::from_secret_key(&scalar).serialize_compressed();
            let r = U256::from_big_endian(&point[1..]);
            assert!(!r.is_zero() && r < SECP256K1N);

            let parity = U256::from(point[0] & 1);
            let base_v = if legacy {
                signature.chain_id.map_or_else(
                    || U256::from(27),
                    |chain_id| chain_id * U256::from(2) + U256::from(35),
                )
            } else {
                U256::zero()
            };

            let forged = replace_signature(&bytes, base_v + parity, r, U256::one());
            let parsed = TxSignature::parse(&forged).unwrap();
            assert_eq!(parsed.signing_hash, signature.signing_hash);
            assert!(parsed.recover_public_key(legacy).is_none());

            // The opposite parity gives -R, so the resulting public key is finite.
            let opposite =
                replace_signature(&bytes, base_v + (U256::one() - parity), r, U256::one());
            assert!(
                TxSignature::parse(&opposite)
                    .unwrap()
                    .recover_public_key(legacy)
                    .is_some()
            );
        }
    }

    #[test]
    fn blob_sidecar_is_excluded_from_signing_hash() {
        let (encoded, _) = SIGNED_TRANSACTIONS[4];
        let bytes = hex::decode(encoded).unwrap();
        let bare = TxSignature::parse(&bytes).unwrap();
        let mut stream = RlpStream::new_list(4);
        stream.append_raw(&bytes[1..], 1);
        // Sidecar contents do not participate in signature recovery.
        for _ in 0..3 {
            stream.begin_list(1).append(&vec![0x42u8; 48]);
        }

        let mut wrapped = vec![3];
        wrapped.extend(stream.out());
        let parsed = TxSignature::parse(&wrapped).unwrap();
        assert_eq!(parsed.signing_hash, bare.signing_hash);
        assert_eq!(parsed.chain_id, bare.chain_id);
        assert_eq!(
            parsed.recover_public_key(false),
            bare.recover_public_key(false)
        );
    }
}
