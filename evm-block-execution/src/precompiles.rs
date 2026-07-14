//! Concrete precompile set passed to the Aurora `StackExecutor`.
//!
//! Ported from `evm-tests` (the harness proven on ~187k state tests). Precompiles come from
//! `aurora-engine-precompiles`; the EIP-4844 point-evaluation precompile (`0x0a`) is the safe
//! KZG implementation in [`kzg`]. The set is selected per hardfork via [`Precompiles::new`].

mod kzg;

use crate::precompiles::kzg::Kzg;
use crate::spec::Spec;
use aurora_engine_precompiles::modexp::AuroraModExp;
use aurora_engine_precompiles::{
    alt_bn256::{Bn256Add, Bn256Mul, Bn256Pair},
    blake2::Blake2F,
    bls12_381::{
        BlsG1Add, BlsG1Msm, BlsG2Add, BlsG2Msm, BlsMapFp2ToG2, BlsMapFpToG1, BlsPairingCheck,
    },
    hash::{RIPEMD160, SHA256},
    identity::Identity,
    modexp::ModExp,
    secp256k1::ECRecover,
    secp256r1::Secp256r1,
    Berlin, Byzantium, EthGas, Istanbul, Osaka, Precompile,
};
use aurora_evm::executor::stack::{
    PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileSet,
};
use aurora_evm::{ExitError, ExitSucceed, Opcode};
use primitive_types::H160;
use std::collections::BTreeMap;

/// Hardfork-specific set of precompiles keyed by address.
pub struct Precompiles(BTreeMap<H160, Box<dyn Precompile>>);

impl PrecompileSet for Precompiles {
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<PrecompileOutput, PrecompileFailure>> {
        let precompile = self.0.get(&handle.code_address())?;
        let result = process_precompile(precompile.as_ref(), handle);
        Some(result.and_then(|output| post_process(output, handle)))
    }

    fn is_precompile(&self, address: H160) -> bool {
        self.0.contains_key(&address)
    }
}

impl Precompiles {
    /// Builds the precompile set for the given hardfork.
    #[must_use]
    pub fn new(spec: &Spec) -> Self {
        match spec {
            Spec::Istanbul => Self::new_istanbul(),
            Spec::Berlin | Spec::London | Spec::Merge | Spec::Shanghai => Self::new_berlin(),
            Spec::Cancun => Self::new_cancun(),
            Spec::Prague => Self::new_prague(),
            Spec::Osaka => Self::new_osaka(),
        }
    }

    /// Istanbul precompile set (ecrecover, sha256, ripemd160, identity, modexp, bn256, blake2f).
    #[must_use]
    pub fn new_istanbul() -> Self {
        let mut map: BTreeMap<H160, Box<dyn Precompile>> = BTreeMap::new();
        map.insert(ECRecover::ADDRESS.raw(), Box::new(ECRecover));
        map.insert(SHA256::ADDRESS.raw(), Box::new(SHA256));
        map.insert(RIPEMD160::ADDRESS.raw(), Box::new(RIPEMD160));
        map.insert(Identity::ADDRESS.raw(), Box::new(Identity));
        map.insert(
            ModExp::<Byzantium, AuroraModExp>::ADDRESS.raw(),
            Box::new(ModExp::<Byzantium, AuroraModExp>::new()),
        );
        map.insert(
            Bn256Add::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Add::<Istanbul>::new()),
        );
        map.insert(
            Bn256Mul::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Mul::<Istanbul>::new()),
        );
        map.insert(
            Bn256Pair::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Pair::<Istanbul>::new()),
        );
        map.insert(Blake2F::ADDRESS.raw(), Box::new(Blake2F));
        Self(map)
    }

    /// Berlin..Shanghai precompile set (Istanbul set with the Berlin modexp pricing).
    #[must_use]
    pub fn new_berlin() -> Self {
        let mut map: BTreeMap<H160, Box<dyn Precompile>> = BTreeMap::new();
        map.insert(ECRecover::ADDRESS.raw(), Box::new(ECRecover));
        map.insert(SHA256::ADDRESS.raw(), Box::new(SHA256));
        map.insert(RIPEMD160::ADDRESS.raw(), Box::new(RIPEMD160));
        map.insert(Identity::ADDRESS.raw(), Box::new(Identity));
        map.insert(
            ModExp::<Berlin, AuroraModExp>::ADDRESS.raw(),
            Box::new(ModExp::<Berlin, AuroraModExp>::new()),
        );
        map.insert(
            Bn256Add::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Add::<Istanbul>::new()),
        );
        map.insert(
            Bn256Mul::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Mul::<Istanbul>::new()),
        );
        map.insert(
            Bn256Pair::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Pair::<Istanbul>::new()),
        );
        map.insert(Blake2F::ADDRESS.raw(), Box::new(Blake2F));
        Self(map)
    }

    /// Cancun precompile set (Berlin set plus the EIP-4844 KZG point evaluation).
    #[must_use]
    pub fn new_cancun() -> Self {
        let mut map = Self::new_berlin().0;
        map.insert(Kzg::ADDRESS, Box::new(Kzg));
        Self(map)
    }

    /// Prague precompile set (Cancun set plus the EIP-2537 BLS12-381 precompiles).
    #[must_use]
    pub fn new_prague() -> Self {
        let mut map = Self::new_cancun().0;
        map.insert(BlsG1Add::ADDRESS.raw(), Box::new(BlsG1Add));
        map.insert(BlsG1Msm::ADDRESS.raw(), Box::new(BlsG1Msm));
        map.insert(BlsG2Add::ADDRESS.raw(), Box::new(BlsG2Add));
        map.insert(BlsG2Msm::ADDRESS.raw(), Box::new(BlsG2Msm));
        map.insert(BlsPairingCheck::ADDRESS.raw(), Box::new(BlsPairingCheck));
        map.insert(BlsMapFpToG1::ADDRESS.raw(), Box::new(BlsMapFpToG1));
        map.insert(BlsMapFp2ToG2::ADDRESS.raw(), Box::new(BlsMapFp2ToG2));
        Self(map)
    }

    /// Osaka precompile set (Prague set with the Osaka modexp pricing).
    #[must_use]
    pub fn new_osaka() -> Self {
        let mut map: BTreeMap<H160, Box<dyn Precompile>> = BTreeMap::new();
        map.insert(ECRecover::ADDRESS.raw(), Box::new(ECRecover));
        map.insert(SHA256::ADDRESS.raw(), Box::new(SHA256));
        map.insert(RIPEMD160::ADDRESS.raw(), Box::new(RIPEMD160));
        map.insert(Identity::ADDRESS.raw(), Box::new(Identity));
        map.insert(
            ModExp::<Osaka, AuroraModExp>::ADDRESS.raw(),
            Box::new(ModExp::<Osaka, AuroraModExp>::new()),
        );
        map.insert(
            Bn256Add::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Add::<Istanbul>::new()),
        );
        map.insert(
            Bn256Mul::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Mul::<Istanbul>::new()),
        );
        map.insert(
            Bn256Pair::<Istanbul>::ADDRESS.raw(),
            Box::new(Bn256Pair::<Istanbul>::new()),
        );
        map.insert(Blake2F::ADDRESS.raw(), Box::new(Blake2F));
        map.insert(Kzg::ADDRESS, Box::new(Kzg));
        map.insert(BlsG1Add::ADDRESS.raw(), Box::new(BlsG1Add));
        map.insert(BlsG1Msm::ADDRESS.raw(), Box::new(BlsG1Msm));
        map.insert(BlsG2Add::ADDRESS.raw(), Box::new(BlsG2Add));
        map.insert(BlsG2Msm::ADDRESS.raw(), Box::new(BlsG2Msm));
        map.insert(BlsPairingCheck::ADDRESS.raw(), Box::new(BlsPairingCheck));
        map.insert(BlsMapFpToG1::ADDRESS.raw(), Box::new(BlsMapFpToG1));
        map.insert(BlsMapFp2ToG2::ADDRESS.raw(), Box::new(BlsMapFp2ToG2));
        // EIP-7951: secp256r1 (P256VERIFY) at address 0x100, introduced in Osaka/Fusaka.
        map.insert(Secp256r1::ADDRESS.raw(), Box::new(Secp256r1));
        Self(map)
    }
}

fn process_precompile(
    precompile: &dyn Precompile,
    handle: &impl PrecompileHandle,
) -> Result<aurora_engine_precompiles::PrecompileOutput, PrecompileFailure> {
    let input = handle.input();
    let gas_limit = handle.gas_limit();
    let evm_context = handle.context();
    let context = aurora_engine_precompiles::Context {
        address: evm_context.address,
        caller: evm_context.caller,
        apparent_value: evm_context.apparent_value,
    };
    let is_static = handle.is_static();

    precompile
        .run(input, gas_limit.map(EthGas::new), &context, is_static)
        .map_err(|err| PrecompileFailure::Error {
            exit_status: map_exit_error(err),
        })
}

fn post_process(
    output: aurora_engine_precompiles::PrecompileOutput,
    handle: &mut impl PrecompileHandle,
) -> Result<PrecompileOutput, PrecompileFailure> {
    handle.record_cost(output.cost.as_u64())?;
    Ok(PrecompileOutput {
        exit_status: ExitSucceed::Stopped,
        output: output.output,
    })
}

fn map_exit_error(exit_error: aurora_engine_precompiles::ExitError) -> ExitError {
    use aurora_engine_precompiles::ExitError as Src;
    match exit_error {
        Src::StackUnderflow => ExitError::StackUnderflow,
        Src::StackOverflow => ExitError::StackOverflow,
        Src::InvalidJump => ExitError::InvalidJump,
        Src::InvalidRange => ExitError::InvalidRange,
        Src::DesignatedInvalid => ExitError::DesignatedInvalid,
        Src::CallTooDeep => ExitError::CallTooDeep,
        Src::CreateCollision => ExitError::CreateCollision,
        Src::CreateContractLimit => ExitError::CreateContractLimit,
        Src::InvalidCode(op) => ExitError::InvalidCode(Opcode(op.0)),
        Src::OutOfOffset => ExitError::OutOfOffset,
        Src::OutOfGas => ExitError::OutOfGas,
        Src::OutOfFund => ExitError::OutOfFund,
        Src::PCUnderflow => ExitError::PCUnderflow,
        Src::CreateEmpty => ExitError::CreateEmpty,
        Src::Other(msg) => ExitError::Other(msg),
        Src::MaxNonce => ExitError::MaxNonce,
        Src::UsizeOverflow => ExitError::UsizeOverflow,
        Src::CreateContractStartingWithEF => ExitError::CreateContractStartingWithEF,
    }
}

#[cfg(test)]
mod tests {
    use super::Precompiles;
    use crate::spec::Spec;
    use aurora_evm::executor::stack::PrecompileSet;
    use primitive_types::H160;

    fn addr(byte: u8) -> H160 {
        H160::from_low_u64_be(u64::from(byte))
    }

    #[test]
    fn istanbul_has_core_precompiles() {
        let set = Precompiles::new(&Spec::Istanbul);
        // 0x01..=0x09 are present (ecrecover..blake2f); KZG (0x0a) is not.
        for byte in 1u8..=9 {
            assert!(
                set.is_precompile(addr(byte)),
                "missing precompile {byte:#x}"
            );
        }
        assert!(!set.is_precompile(addr(0x0a)));
    }

    #[test]
    fn cancun_adds_kzg() {
        let set = Precompiles::new(&Spec::Cancun);
        assert!(set.is_precompile(addr(0x0a)));
    }

    #[test]
    fn prague_adds_bls() {
        let set = Precompiles::new(&Spec::Prague);
        // EIP-2537 BLS precompiles occupy 0x0b..=0x11.
        for byte in 0x0bu8..=0x11 {
            assert!(
                set.is_precompile(addr(byte)),
                "missing BLS precompile {byte:#x}"
            );
        }
    }

    #[test]
    fn osaka_adds_p256verify() {
        // EIP-7951 secp256r1 (P256VERIFY) lives at 0x100 and is introduced in Osaka.
        let p256 = H160::from_low_u64_be(0x100);
        assert!(Precompiles::new(&Spec::Osaka).is_precompile(p256));
        // It must NOT be present before Osaka.
        assert!(!Precompiles::new(&Spec::Prague).is_precompile(p256));
    }
}
