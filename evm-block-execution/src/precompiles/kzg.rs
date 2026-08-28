//! EIP-4844 point-evaluation precompile (`0x0A`).

use aurora_engine_precompiles::{
    Context, EthGas, EvmPrecompileResult, ExitError, Precompile, PrecompileOutput,
};
use c_kzg::{Bytes32, Bytes48, ethereum_kzg_settings};
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

        // In c-kzg 2.x, `verify_kzg_proof` is a method on the settings (was an associated function
        // taking the settings). `precompute = 0` keeps trusted-setup loading cheap.
        let verified = ethereum_kzg_settings(0)
            .verify_kzg_proof(&commitment, &z, &y, &proof)
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

#[cfg(test)]
mod tests {
    use super::Kzg;
    use aurora_engine_precompiles::{Context, EthGas, ExitError, Precompile};
    use hex_literal::hex;
    use primitive_types::{H160, U256};

    /// c-kzg `verify_kzg_proof_case_correct_proof_4_4`, also used by REVM.
    const VALID_INPUT: [u8; 192] = hex!(
        "01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f549b"
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"
        "1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9"
        "8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca2"
        "5f26936857bc3a7c2539ea8ec3a952b7"
        "a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc216074"
        "4faf0070725e00b60ad9a026a15b1a8c"
    );

    /// Invalid proof vector from REVM's EIP-4844 precompile tests.
    const INVALID_PROOF_INPUT: [u8; 192] = hex!(
        "010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
        "c000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000"
        "c000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000"
    );

    const EXPECTED_OUTPUT: [u8; 64] = hex!(
        "0000000000000000000000000000000000000000000000000000000000001000"
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
    );

    fn context() -> Context {
        Context {
            address: Kzg::ADDRESS,
            caller: H160::zero(),
            apparent_value: U256::zero(),
        }
    }

    #[test]
    fn official_vector_matches_address_gas_and_output() {
        assert_eq!(
            Kzg::ADDRESS,
            H160(hex!("000000000000000000000000000000000000000a"))
        );

        let output = Kzg
            .run(&VALID_INPUT, Some(EthGas::new(50_000)), &context(), true)
            .unwrap();
        assert_eq!(output.cost.as_u64(), 50_000);
        assert_eq!(output.output, EXPECTED_OUTPUT);
        assert!(output.logs.is_empty());
    }

    #[test]
    fn insufficient_gas_is_rejected_before_evaluation() {
        assert!(matches!(
            Kzg.run(&VALID_INPUT, Some(EthGas::new(49_999)), &context(), true),
            Err(ExitError::OutOfGas)
        ));
    }

    #[test]
    fn mismatched_versioned_hash_is_rejected() {
        let mut input = VALID_INPUT;
        input[0] ^= 0x01;

        assert!(matches!(
            Kzg.run(&input, Some(EthGas::new(50_000)), &context(), true),
            Err(ExitError::Other(message)) if message == "BlobMismatchedVersion"
        ));
    }

    #[test]
    fn invalid_proof_is_rejected() {
        assert!(matches!(
            Kzg.run(
                &INVALID_PROOF_INPUT,
                Some(EthGas::new(50_000)),
                &context(),
                true
            ),
            Err(ExitError::Other(message)) if message == "BlobVerifyKzgProofFailed"
        ));
    }
}
