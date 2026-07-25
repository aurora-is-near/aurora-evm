#![allow(clippy::module_inception)]

use aurora_engine_precompiles::{
    Context, EthGas, EvmPrecompileResult, ExitError, Precompile, PrecompileOutput,
};
use primitive_types::H160;
use std::borrow::Cow::Borrowed;

mod kzg {
    use c_kzg::{Bytes32, Bytes48, KzgSettings, ethereum_kzg_settings};
    use core::convert::TryInto;
    use hex_literal::hex;
    use sha2::Digest;
    use std::convert::TryFrom;

    pub const RETURN_VALUE: &[u8; 64] = &hex!(
        "0000000000000000000000000000000000000000000000000000000000001000"
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
    );

    /// Mainnet KZG trusted setup, bundled with `c-kzg` and loaded once (EIP-4844).
    ///
    /// c-kzg 2.x dropped the two-argument `KzgSettings::load_trusted_setup(g1, g2)` — the setup now
    /// needs g1-monomial, g1-lagrange and g2-monomial points plus a `precompute` value — so instead
    /// of hand-parsing a trusted-setup file we use the mainnet setup `c-kzg` ships, which is exactly
    /// what these tests need. `precompute = 0` keeps loading cheap, suiting a one-shot test run.
    pub fn default_settings() -> &'static KzgSettings {
        ethereum_kzg_settings(0)
    }

    /// `VERSIONED_HASH_VERSION_KZG ++ sha256(commitment)[1..]`
    #[inline]
    pub fn kzg_to_versioned_hash(commitment: &[u8]) -> [u8; 32] {
        const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;
        let mut hash: [u8; 32] = sha2::Sha256::digest(commitment).into();
        hash[0] = VERSIONED_HASH_VERSION_KZG;
        hash
    }

    #[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
    pub struct KzgInput {
        commitment: Bytes48,
        z: Bytes32,
        y: Bytes32,
        proof: Bytes48,
    }

    impl KzgInput {
        #[inline]
        pub fn verify_kzg_proof(&self, kzg_settings: &KzgSettings) -> bool {
            kzg_settings
                .verify_kzg_proof(&self.commitment, &self.z, &self.y, &self.proof)
                .unwrap_or(false)
        }
    }

    impl TryFrom<&[u8]> for KzgInput {
        type Error = &'static str;

        fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
            if input.len() != 192 {
                return Err("BlobInvalidInputLength");
            }
            // Verify commitment matches versioned_hash
            let versioned_hash = &input[..32];
            let commitment = &input[96..144];
            if kzg_to_versioned_hash(commitment) != versioned_hash {
                return Err("BlobMismatchedVersion");
            }
            let commitment = *as_bytes48(commitment);
            let z = *as_bytes32(&input[32..64]);
            let y = *as_bytes32(&input[64..96]);
            let proof = *as_bytes48(&input[144..192]);
            Ok(Self {
                commitment,
                z,
                y,
                proof,
            })
        }
    }

    #[inline]
    fn as_array<const N: usize>(bytes: &[u8]) -> &[u8; N] {
        bytes.try_into().expect("slice with incorrect length")
    }

    #[inline]
    fn as_bytes32(bytes: &[u8]) -> &Bytes32 {
        // SAFETY: `#[repr(C)] Bytes32([u8; 32])`
        unsafe { &*as_array::<32>(bytes).as_ptr().cast() }
    }

    #[inline]
    fn as_bytes48(bytes: &[u8]) -> &Bytes48 {
        // SAFETY: `#[repr(C)] Bytes48([u8; 48])`
        unsafe { &*as_array::<48>(bytes).as_ptr().cast() }
    }
}

const KZG_BASE_GAS_FEE: u64 = 50_000;

pub struct Kzg;

impl Kzg {
    pub const ADDRESS: H160 = H160([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0A,
    ]);

    fn execute(input: &[u8]) -> Result<Vec<u8>, ExitError> {
        // Get and verify KZG input against the bundled mainnet trusted setup.
        let kzg_input: kzg::KzgInput = input
            .try_into()
            .map_err(|e| ExitError::Other(Borrowed(e)))?;
        if !kzg_input.verify_kzg_proof(kzg::default_settings()) {
            return Err(ExitError::Other(Borrowed("BlobVerifyKzgProofFailed")));
        }
        Ok(kzg::RETURN_VALUE.to_vec())
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
        if let Some(target_gas) = target_gas
            && cost > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        let output = Self::execute(input)?;
        Ok(PrecompileOutput::without_logs(cost, output))
    }
}
