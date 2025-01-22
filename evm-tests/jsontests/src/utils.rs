use evm::backend::MemoryAccount;
use evm::ExitError;
use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};
use std::borrow::Cow;
use std::collections::BTreeMap;

pub fn u256_to_h256(u: U256) -> H256 {
	H256(u.to_big_endian())
}

pub fn unwrap_to_account(s: &ethjson::spec::Account) -> MemoryAccount {
	MemoryAccount {
		balance: s.balance.unwrap().into(),
		nonce: s.nonce.unwrap().0,
		code: s.code.clone().unwrap().into(),
		storage: s
			.storage
			.as_ref()
			.unwrap()
			.iter()
			.filter_map(|(k, v)| {
				if v.0.is_zero() {
					// If value is zero then the key is not really there
					None
				} else {
					Some((u256_to_h256((*k).into()), u256_to_h256((*v).into())))
				}
			})
			.collect(),
	}
}

pub fn unwrap_to_state(a: &ethjson::spec::State) -> BTreeMap<H160, MemoryAccount> {
	match &a.0 {
		ethjson::spec::HashOrMap::Map(m) => m
			.iter()
			.map(|(k, v)| ((*k).into(), unwrap_to_account(v)))
			.collect(),
		ethjson::spec::HashOrMap::Hash(_) => panic!("Hash can not be converted."),
	}
}

/// Basic account type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieAccount {
	/// Nonce of the account.
	pub nonce: U256,
	/// Balance of the account.
	pub balance: U256,
	/// Storage root of the account.
	pub storage_root: H256,
	/// Code hash of the account.
	pub code_hash: H256,
	/// Code version of the account.
	pub code_version: U256,
}

impl rlp::Encodable for TrieAccount {
	fn rlp_append(&self, stream: &mut rlp::RlpStream) {
		let use_short_version = self.code_version == U256::zero();

		match use_short_version {
			true => {
				stream.begin_list(4);
			}
			false => {
				stream.begin_list(5);
			}
		}

		stream.append(&self.nonce);
		stream.append(&self.balance);
		stream.append(&self.storage_root);
		stream.append(&self.code_hash);

		if !use_short_version {
			stream.append(&self.code_version);
		}
	}
}

impl rlp::Decodable for TrieAccount {
	fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
		let use_short_version = match rlp.item_count()? {
			4 => true,
			5 => false,
			_ => return Err(rlp::DecoderError::RlpIncorrectListLen),
		};

		Ok(Self {
			nonce: rlp.val_at(0)?,
			balance: rlp.val_at(1)?,
			storage_root: rlp.val_at(2)?,
			code_hash: rlp.val_at(3)?,
			code_version: if use_short_version {
				U256::zero()
			} else {
				rlp.val_at(4)?
			},
		})
	}
}

pub fn check_valid_hash(h: &H256, b: &BTreeMap<H160, MemoryAccount>) -> (bool, H256) {
	let tree = b
		.iter()
		.map(|(address, account)| {
			let storage_root = H256(
				ethereum::util::sec_trie_root(
					account
						.storage
						.iter()
						.map(|(k, v)| (k, rlp::encode(&U256::from_big_endian(&v[..])))),
				)
				.0,
			);
			let code_hash = H256::from_slice(Keccak256::digest(&account.code).as_slice());

			let account = TrieAccount {
				nonce: account.nonce,
				balance: account.balance,
				storage_root,
				code_hash,
				code_version: U256::zero(),
			};
			(address, rlp::encode(&account))
		})
		.collect::<Vec<_>>();

	let root = H256(ethereum::util::sec_trie_root(tree).0);
	let expect = h;
	(root == *expect, root)
}

pub fn flush() {
	use std::io::{self, Write};

	io::stdout().flush().expect("Could not flush stdout");
}

/// EIP-7623 form Prague hard fork
pub mod eip7623 {
	/// The standard cost of calldata token.
	pub const STANDARD_TOKEN_COST: usize = 4;
	/// The cost of a non-zero byte in calldata adjusted by [EIP-2028](https://eips.ethereum.org/EIPS/eip-2028).
	pub const NON_ZERO_BYTE_DATA_COST: usize = 16;
	/// The multiplier for a non zero byte in calldata adjusted by [EIP-2028](https://eips.ethereum.org/EIPS/eip-2028).
	pub const NON_ZERO_BYTE_MULTIPLIER: usize = NON_ZERO_BYTE_DATA_COST / STANDARD_TOKEN_COST;
	// The cost floor per token
	pub const TOTAL_COST_FLOOR_PER_TOKEN: u64 = 10;

	/// Retrieve the total number of tokens in calldata.
	#[must_use]
	pub fn get_tokens_in_calldata(input: &[u8]) -> u64 {
		let zero_data_len = input.iter().filter(|v| **v == 0).count();
		let non_zero_data_len = input.len() - zero_data_len;
		u64::try_from(zero_data_len + non_zero_data_len * NON_ZERO_BYTE_MULTIPLIER).unwrap()
	}

	/// Calculate the transaction cost floor as specified in EIP-7623.
	#[must_use]
	pub const fn calc_tx_floor_cost(tokens_in_calldata: u64) -> u64 {
		tokens_in_calldata * TOTAL_COST_FLOOR_PER_TOKEN + 21_000
	}
}

/// EIP-7702
pub mod eip7702 {
	use super::{Digest, Keccak256, H160, H256, U256};
	use evm::ExitError;
	use rlp::RlpStream;

	pub const MAGIC: u8 = 0x5;
	/// The order of the secp256k1 curve, divided by two. Signatures that should be checked according
	/// to EIP-2 should have an S value less than or equal to this.
	///
	/// `57896044618658097711785492504343953926418782139537452191302581570759080747168`
	pub const SECP256K1N_HALF: U256 = U256([
		0xDFE92F46681B20A0,
		0x5D576E7357A4501D,
		0xFFFFFFFFFFFFFFFF,
		0x7FFFFFFFFFFFFFFF,
	]);

	#[derive(Debug, Clone, PartialEq, Eq)]
	pub struct Authorization {
		pub chain_id: U256,
		pub address: H160,
		pub nonce: u64,
	}

	impl Authorization {
		#[must_use]
		pub const fn new(chain_id: U256, address: H160, nonce: u64) -> Self {
			Self {
				chain_id,
				address,
				nonce,
			}
		}

		fn rlp_append(&self, s: &mut RlpStream) {
			s.begin_list(3);
			s.append(&self.chain_id);
			s.append(&self.address);
			s.append(&self.nonce);
		}

		pub fn signature_hash(&self) -> H256 {
			let mut rlp_stream = RlpStream::new();
			rlp_stream.append(&MAGIC);
			self.rlp_append(&mut rlp_stream);
			H256::from_slice(Keccak256::digest(rlp_stream.as_raw()).as_slice())
		}
	}

	#[derive(Debug, Clone, PartialEq, Eq)]
	pub struct SignedAuthorization {
		chain_id: U256,
		address: H160,
		nonce: u64,
		v: bool,
		r: U256,
		s: U256,
	}

	impl SignedAuthorization {
		#[must_use]
		pub const fn new(
			chain_id: U256,
			address: H160,
			nonce: u64,
			r: U256,
			s: U256,
			v: bool,
		) -> Self {
			Self {
				chain_id,
				address,
				nonce,
				s,
				r,
				v,
			}
		}

		pub fn recover_address(&self) -> Result<H160, ExitError> {
			let auth = Authorization::new(self.chain_id, self.address, self.nonce).signature_hash();
			super::ecrecover(auth, &super::vrs_to_arr(self.v, self.r, self.s))
		}
	}
}

/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
pub mod eip_4844 {
	use super::U256;

	/// EIP-4844 constants
	/// Gas consumption of a single data blob (== blob byte size).
	pub const GAS_PER_BLOB: u64 = 1 << 17;
	/// Target number of the blob per block.
	pub const TARGET_BLOB_NUMBER_PER_BLOCK: u64 = 3;
	/// Max number of blobs per block
	pub const MAX_BLOB_NUMBER_PER_BLOCK: u64 = 2 * TARGET_BLOB_NUMBER_PER_BLOCK;
	/// Target consumable blob gas for data blobs per block (for 1559-like pricing).
	pub const TARGET_BLOB_GAS_PER_BLOCK: u64 = TARGET_BLOB_NUMBER_PER_BLOCK * GAS_PER_BLOB;
	/// Minimum gas price for data blobs.
	pub const MIN_BLOB_GASPRICE: u64 = 1;
	/// Controls the maximum rate of change for blob gas price.
	pub const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3338477;
	/// First version of the blob.
	pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

	/// Calculates the `excess_blob_gas` from the parent header's `blob_gas_used` and `excess_blob_gas`.
	///
	/// See also [the EIP-4844 helpers]<https://eips.ethereum.org/EIPS/eip-4844#helpers>
	/// (`calc_excess_blob_gas`).
	#[inline]
	pub const fn calc_excess_blob_gas(
		parent_excess_blob_gas: u64,
		parent_blob_gas_used: u64,
	) -> u64 {
		(parent_excess_blob_gas + parent_blob_gas_used).saturating_sub(TARGET_BLOB_GAS_PER_BLOCK)
	}

	/// Calculates the blob gas price from the header's excess blob gas field.
	///
	/// See also [the EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
	/// (`get_blob_gasprice`).
	#[inline]
	pub fn calc_blob_gas_price(excess_blob_gas: u64) -> u128 {
		fake_exponential(
			MIN_BLOB_GASPRICE,
			excess_blob_gas,
			BLOB_GASPRICE_UPDATE_FRACTION,
		)
	}

	/// See [EIP-4844], [`calc_max_data_fee`]
	///
	/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
	#[inline]
	pub const fn get_total_blob_gas(blob_hashes_len: usize) -> u64 {
		GAS_PER_BLOB * blob_hashes_len as u64
	}

	/// Calculates the [EIP-4844] `data_fee` of the transaction.
	///
	/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
	#[inline]
	pub fn calc_max_data_fee(max_fee_per_blob_gas: U256, blob_hashes_len: usize) -> U256 {
		max_fee_per_blob_gas.saturating_mul(U256::from(get_total_blob_gas(blob_hashes_len)))
	}

	/// Calculates the [EIP-4844] `data_fee` of the transaction.
	///
	/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
	#[inline]
	pub fn calc_data_fee(blob_gas_price: u128, blob_hashes_len: usize) -> U256 {
		U256::from(blob_gas_price).saturating_mul(U256::from(get_total_blob_gas(blob_hashes_len)))
	}

	/// Approximates `factor * e ** (numerator / denominator)` using Taylor expansion.
	///
	/// This is used to calculate the blob price.
	///
	/// See also [the EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
	/// (`fake_exponential`).
	///
	/// # Panics
	///
	/// This function panics if `denominator` is zero.
	///
	/// # NOTES
	/// PLEASE DO NOT USE IN PRODUCTION as not checked overflow. For tests only.
	#[inline]
	pub fn fake_exponential(factor: u64, numerator: u64, denominator: u64) -> u128 {
		assert_ne!(denominator, 0, "attempt to divide by zero");
		let factor = factor as u128;
		let numerator = numerator as u128;
		let denominator = denominator as u128;

		let mut i = 1;
		let mut output = 0;
		let mut numerator_accum = factor * denominator;
		while numerator_accum > 0 {
			output += numerator_accum;

			// Denominator is asserted as not zero at the start of the function.
			numerator_accum = (numerator_accum * numerator) / (denominator * i);
			i += 1;
		}
		output / denominator
	}
}

pub mod transaction {
	use crate::state::TxType;
	use crate::utils::{eip7623, eip7702};
	use ethjson::hash::Address;
	use ethjson::maybe::MaybeEmpty;
	use ethjson::spec::ForkSpec;
	use ethjson::test_helpers::state::{MultiTransaction, PostStateResult};
	use ethjson::transaction::Transaction;
	use ethjson::uint::Uint;
	use evm::backend::MemoryVicinity;
	use evm::executor::stack::Authorization;
	use evm::gasometer::{self, Gasometer};
	use primitive_types::{H160, H256, U256};

	// TODO: it will be refactored as old solution inefficient, also will be removed clippy-allow flag
	#[allow(clippy::too_many_arguments)]
	pub fn validate(
		tx: &Transaction,
		block_gas_limit: U256,
		caller_balance: U256,
		config: &evm::Config,
		test_tx: &MultiTransaction,
		vicinity: &MemoryVicinity,
		blob_gas_price: Option<u128>,
		data_fee: Option<U256>,
		spec: &ForkSpec,
		tx_state: &PostStateResult,
	) -> Result<Vec<Authorization>, InvalidTxReason> {
		let mut authorization_list: Vec<Authorization> = vec![];
		match intrinsic_gas(tx, config) {
			None => return Err(InvalidTxReason::IntrinsicGas),
			Some(required_gas) => {
				if tx.gas_limit < Uint(U256::from(required_gas)) {
					return Err(InvalidTxReason::IntrinsicGas);
				}
			}
		}

		if block_gas_limit < tx.gas_limit.0 {
			return Err(InvalidTxReason::GasLimitReached);
		}

		let required_funds = tx
			.gas_limit
			.0
			.checked_mul(vicinity.gas_price)
			.ok_or(InvalidTxReason::OutOfFund)?
			.checked_add(tx.value.0)
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
		// Presence of max_fee_per_blob_gas means that this is blob transaction.
		if *spec >= ForkSpec::Cancun {
			if let Some(max) = test_tx.max_fee_per_blob_gas {
				// ensure that the user was willing to at least pay the current blob gasprice
				if U256::from(blob_gas_price.expect("expect blob_gas_price")) > max.0 {
					return Err(InvalidTxReason::BlobGasPriceGreaterThanMax);
				}

				// there must be at least one blob
				if test_tx.blob_versioned_hashes.is_empty() {
					return Err(InvalidTxReason::EmptyBlobs);
				}

				// The field `to` deviates slightly from the semantics with the exception
				// that it MUST NOT be nil and therefore must always represent
				// a 20-byte address. This means that blob transactions cannot
				// have the form of a create transaction.
				let to_address: Option<Address> = test_tx.to.clone().into();
				if to_address.is_none() {
					return Err(InvalidTxReason::BlobCreateTransaction);
				}

				// all versioned blob hashes must start with VERSIONED_HASH_VERSION_KZG
				for blob in test_tx.blob_versioned_hashes.iter() {
					let blob_hash = H256(blob.to_big_endian());
					if blob_hash[0] != super::eip_4844::VERSIONED_HASH_VERSION_KZG {
						return Err(InvalidTxReason::BlobVersionNotSupported);
					}
				}

				// ensure the total blob gas spent is at most equal to the limit
				// assert blob_gas_used <= MAX_BLOB_GAS_PER_BLOCK
				if test_tx.blob_versioned_hashes.len()
					> super::eip_4844::MAX_BLOB_NUMBER_PER_BLOCK as usize
				{
					return Err(InvalidTxReason::TooManyBlobs);
				}
			}
		} else {
			if !test_tx.blob_versioned_hashes.is_empty() {
				return Err(InvalidTxReason::BlobVersionedHashesNotSupported);
			}
			if test_tx.max_fee_per_blob_gas.is_some() {
				return Err(InvalidTxReason::MaxFeePerBlobGasNotSupported);
			}
		}

		if *spec >= ForkSpec::Prague {
			// EIP-7623 validation
			let floor_gas = eip7623::calc_tx_floor_cost(eip7623::get_tokens_in_calldata(&tx.data));
			if floor_gas > tx.gas_limit.into() {
				return Err(InvalidTxReason::GasFloorMoreThanGasLimit);
			}

			// EIP-7702 - if transaction type is EOAAccountCode then
			// `authorization_list` must be present
			if TxType::from_txbytes(&tx_state.txbytes) == TxType::EOAAccountCode
				&& test_tx.authorization_list.is_empty()
			{
				return Err(InvalidTxReason::AuthorizationListNotExist);
			}

			// Check EIP-7702 Spec validation steps: 1 and 2
			// Other validation step inside EVM transact logic.
			for auth in test_tx.authorization_list.iter() {
				// 1. Verify the chain id is either 0 or the chain’s current ID.
				let mut is_valid = auth.chain_id.0 <= U256::from(u64::MAX)
					&& (auth.chain_id.0 == U256::from(0) || auth.chain_id.0 == vicinity.chain_id);

				// 3. `authority = ecrecover(keccak(MAGIC || rlp([chain_id, address, nonce])), y_parity, r, s]`
				// Validate the signature, as in tests it is possible to have invalid signatures values.
				// Value `v` shouldn't be greater then 1
				let v = auth.v.0;
				if v > U256::from(1) {
					is_valid = false;
				}

				// EIP-2 validation
				if auth.s.0 > eip7702::SECP256K1N_HALF {
					is_valid = false;
				}

				let auth_address = eip7702::SignedAuthorization::new(
					auth.chain_id.0,
					auth.address.0,
					auth.nonce.0.as_u64(),
					auth.r.0,
					auth.s.0,
					auth.v.0.as_u32() > 0,
				)
				.recover_address();
				let auth_address = auth_address.unwrap_or_else(|_| {
					is_valid = false;
					H160::zero()
				});

				authorization_list.push(Authorization {
					authority: auth_address,
					address: auth.address.0,
					nonce: auth.nonce.0.as_u64(),
					is_valid,
				});
			}
		} else if !test_tx.authorization_list.is_empty() {
			return Err(InvalidTxReason::AuthorizationListNotSupported);
		}
		Ok(authorization_list)
	}

	fn intrinsic_gas(tx: &Transaction, config: &evm::Config) -> Option<u64> {
		let is_contract_creation = match tx.to {
			MaybeEmpty::None => true,
			MaybeEmpty::Some(_) => false,
		};
		let data = &tx.data;
		let access_list: Vec<(H160, Vec<H256>)> = tx
			.access_list
			.iter()
			.map(|(a, s)| (a.0, s.iter().map(|h| h.0).collect()))
			.collect();

		// EIP-7702
		let authorization_list_len = tx.authorization_list.len();

		let cost = if is_contract_creation {
			gasometer::create_transaction_cost(data, &access_list)
		} else {
			gasometer::call_transaction_cost(data, &access_list, authorization_list_len)
		};

		let mut g = Gasometer::new(u64::MAX, config);
		g.record_transaction(cost).ok()?;

		Some(g.total_used_gas())
	}

	#[derive(Debug)]
	pub enum InvalidTxReason {
		IntrinsicGas,
		OutOfFund,
		GasLimitReached,
		PriorityFeeTooLarge,
		GasPriceLessThenBlockBaseFee,
		BlobCreateTransaction,
		BlobVersionNotSupported,
		TooManyBlobs,
		EmptyBlobs,
		BlobGasPriceGreaterThanMax,
		BlobVersionedHashesNotSupported,
		MaxFeePerBlobGasNotSupported,
		GasPriseEip1559,
		AuthorizationListNotExist,
		AuthorizationListNotSupported,
		InvalidAuthorizationChain,
		InvalidAuthorizationSignature,
		CreateTransaction,
		GasFloorMoreThanGasLimit,
	}
}

fn ecrecover(hash: H256, signature: &[u8]) -> Result<H160, ExitError> {
	let hash = libsecp256k1::Message::parse_slice(hash.as_bytes())
		.map_err(|e| ExitError::Other(Cow::from(e.to_string())))?;
	let v = signature[64];
	let signature = libsecp256k1::Signature::parse_standard_slice(&signature[0..64])
		.map_err(|e| ExitError::Other(Cow::from(e.to_string())))?;
	let bit = match v {
		0..=26 => v,
		_ => v - 27,
	};

	if let Ok(recovery_id) = libsecp256k1::RecoveryId::parse(bit) {
		if let Ok(public_key) = libsecp256k1::recover(&hash, &signature, &recovery_id) {
			// recover returns a 65-byte key, but addresses come from the raw 64-byte key
			let r = sha3::Keccak256::digest(&public_key.serialize()[1..]);
			return Ok(H160::from_slice(&r[12..]));
		}
	}

	Err(ExitError::Other(Cow::from("ECRecoverErr unknown error")))
}

/// v, r, s signature values to array
fn vrs_to_arr(v: bool, r: U256, s: U256) -> [u8; 65] {
	let mut result = [0u8; 65]; // (r, s, v), typed (uint256, uint256, uint8)
	result[..32].copy_from_slice(&r.to_big_endian());
	result[32..64].copy_from_slice(&s.to_big_endian());
	result[64] = u8::from(v);
	result
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;
	use primitive_types::H160;

	#[test]
	fn test_ecrecover_success() {
		let hash = H256::from_slice(&hex!(
			"47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
		));
		let signature = hex!("650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e031b");
		let expected_address = H160::from_slice(&hex!("c08b5542d177ac6686946920409741463a15dddb"));

		let result = ecrecover(hash, &signature).expect("ecrecover should succeed");
		assert_eq!(result, expected_address);
	}

	#[test]
	fn test_ecrecover_invalid_signature() {
		let hash = H256::from_slice(&hex!(
			"47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
		));
		let signature = hex!("00650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e031c");

		let result = ecrecover(hash, &signature);
		assert_eq!(
			result,
			Err(ExitError::Other(Cow::from("ECRecoverErr unknown error")))
		);
	}

	#[test]
	fn test_ecrecover_invalid_recovery_id() {
		let hash = H256::from_slice(&hex!(
			"47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
		));
		let signature = hex!("650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e0327");

		let result = ecrecover(hash, &signature);
		assert_eq!(
			result,
			Err(ExitError::Other(Cow::from("ECRecoverErr unknown error")))
		);
	}
}
