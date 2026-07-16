//! EIP-4844 point-evaluation precompile (`0x0A`).
//!
//! Safe port of the `evm-tests` KZG precompile: it uses `c_kzg`'s embedded Ethereum mainnet
//! trusted setup and safe `from_bytes` constructors, so it needs no `unsafe` and no embedded
//! asset files (the crate keeps `#![forbid(unsafe_code)]`).

use aurora_engine_precompiles::{
    Context, EthGas, EvmPrecompileResult, ExitError, Precompile, PrecompileOutput,
};
use c_kzg::{Bytes32, Bytes48, KzgProof, ethereum_kzg_settings};
use hex_literal::hex;
use primitive_types::H160;
use sha2::{Digest as _, Sha256};
use std::borrow::Cow::Borrowed;

/// Fixed gas cost of the point-evaluation precompile (EIP-4844).
const KZG_BASE_GAS_FEE: u64 = 50_000;

/// Successful precompile output: `FIELD_ELEMENTS_PER_BLOB` and the BLS modulus.
const RETURN_VALUE: [u8; 64] = hex!(
    "0000000000000000000000000000000000000000000000000000000000001000"
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
);

/// `VERSIONED_HASH_VERSION_KZG || sha256(commitment)[1..]`.
fn kzg_to_versioned_hash(commitment: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(commitment);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash[0] = 0x01; // VERSIONED_HASH_VERSION_KZG
    hash
}

/// EIP-4844 point-evaluation precompile.
pub struct Kzg;

impl Kzg {
    /// Precompile address `0x000...0a`.
    pub const ADDRESS: H160 = H160(hex!("000000000000000000000000000000000000000a"));

    fn execute(input: &[u8]) -> Result<Vec<u8>, ExitError> {
        if input.len() != 192 {
            return Err(ExitError::Other(Borrowed("BlobInvalidInputLength")));
        }
        // Verify the commitment matches the supplied versioned hash.
        if kzg_to_versioned_hash(&input[96..144])[..] != input[..32] {
            return Err(ExitError::Other(Borrowed("BlobMismatchedVersion")));
        }
        let commitment = Bytes48::from_bytes(&input[96..144])
            .map_err(|_err| ExitError::Other(Borrowed("BlobInvalidCommitment")))?;
        let z = Bytes32::from_bytes(&input[32..64])
            .map_err(|_err| ExitError::Other(Borrowed("BlobInvalidZ")))?;
        let y = Bytes32::from_bytes(&input[64..96])
            .map_err(|_err| ExitError::Other(Borrowed("BlobInvalidY")))?;
        let proof = Bytes48::from_bytes(&input[144..192])
            .map_err(|_err| ExitError::Other(Borrowed("BlobInvalidProof")))?;

        let verified =
            KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, ethereum_kzg_settings())
                .unwrap_or(false);
        if !verified {
            return Err(ExitError::Other(Borrowed("BlobVerifyKzgProofFailed")));
        }
        Ok(RETURN_VALUE.to_vec())
    }
}

impl Precompile for Kzg {
    fn required_gas(_input: &[u8]) -> Result<EthGas, ExitError> {
        Ok(EthGas::new(KZG_BASE_GAS_FEE))
    }

    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        _context: &Context,
        _is_static: bool,
    ) -> EvmPrecompileResult {
        let cost = Self::required_gas(input)?;
        if target_gas.is_some_and(|target| cost > target) {
            return Err(ExitError::OutOfGas);
        }
        let output = Self::execute(input)?;
        Ok(PrecompileOutput::without_logs(cost, output))
    }
}
