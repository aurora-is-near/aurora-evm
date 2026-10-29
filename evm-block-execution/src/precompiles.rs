//! Ethereum mainnet precompiled contracts, selected per hardfork.
//!
//! Precompiles run native implementations at fixed addresses instead of EVM bytecode.
//! [`Precompiles::new`] selects the set and pricing for a [`Spec`]:
//!
//! | Hardfork | Addresses | Contents |
//! |---|---|---|
//! | Istanbul | `0x01`–`0x09` | ecrecover, sha256, ripemd160, identity, modexp (Byzantium pricing), bn256 add/mul/pairing, blake2f |
//! | Berlin…Shanghai | `0x01`–`0x09` | the same, modexp repriced per EIP-2565 |
//! | Cancun | + `0x0a` | KZG point evaluation (EIP-4844) |
//! | Prague | + `0x0b`–`0x11` | BLS12-381 operations (EIP-2537) |
//! | Osaka | + `0x100` | P256VERIFY (EIP-7951); modexp repriced per EIP-7883 |
//!
//!
//! One set is shared by every transaction executor in a block. The adapters in this module bridge
//! `aurora-engine-precompiles` to [`PrecompileSet`] and account for gas on the executor handle.

mod kzg;

use crate::precompiles::kzg::Kzg;
use crate::spec::Spec;
use aurora_engine_precompiles::modexp::AuroraModExp;
use aurora_engine_precompiles::{
    Berlin, Byzantium, EthGas, Istanbul, Osaka, Precompile,
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
};
use aurora_evm::executor::stack::{
    PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileSet,
};
use aurora_evm::{ExitError, ExitSucceed, Opcode};
use primitive_types::H160;
use std::collections::BTreeMap;

/// Hardfork-specific set of precompiles, keyed by address.
///
/// Build with [`Precompiles::new`] and pass by reference to
/// `StackExecutor::new_with_precompiles`.
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
        let mut map = Self::new_istanbul().0;
        // EIP-2565 replaces the Byzantium-priced entry at the same address.
        map.insert(
            ModExp::<Berlin, AuroraModExp>::ADDRESS.raw(),
            Box::new(ModExp::<Berlin, AuroraModExp>::new()),
        );
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

    /// Osaka precompile set (Prague set with EIP-7883 modexp pricing, plus P256VERIFY at
    /// `0x100`, EIP-7951).
    #[must_use]
    pub fn new_osaka() -> Self {
        let mut map = Self::new_prague().0;
        // EIP-7883 replaces the Berlin-priced entry at the same address.
        map.insert(
            ModExp::<Osaka, AuroraModExp>::ADDRESS.raw(),
            Box::new(ModExp::<Osaka, AuroraModExp>::new()),
        );
        // EIP-7951: secp256r1 (P256VERIFY) at address 0x100, introduced in Osaka/Fusaka.
        map.insert(Secp256r1::ADDRESS.raw(), Box::new(Secp256r1));
        Self(map)
    }
}

/// Runs a precompile through the `aurora-engine-precompiles` API, translating the call context.
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

/// Records the precompile's gas cost on the executor handle and converts the output type.
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

/// Maps `aurora-engine-precompiles` exit errors onto the executor's [`ExitError`].
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
    use super::{
        AuroraModExp, Berlin, BlsG1Add, BlsG1Msm, BlsG2Add, BlsG2Msm, BlsMapFp2ToG2, BlsMapFpToG1,
        BlsPairingCheck, EthGas, Kzg, ModExp, Precompiles, Secp256r1,
    };
    use crate::spec::Spec;
    use aurora_evm::executor::stack::PrecompileSet;
    use primitive_types::{H160, U256};
    use std::collections::BTreeSet;

    /// Smallest well-formed modexp call: three 32-byte lengths of 1, then `base, exp, mod`.
    const TRIVIAL_MODEXP: [u8; 99] = {
        let mut input = [0u8; 99];
        input[31] = 1;
        input[63] = 1;
        input[95] = 1;
        input[96] = 1;
        input[97] = 1;
        input[98] = 1;
        input
    };

    fn addresses(set: &Precompiles) -> BTreeSet<H160> {
        set.0.keys().copied().collect()
    }

    /// Cost of `0x05` on a trivial input, which lands on each pricing's floor.
    fn modexp_cost(set: &Precompiles) -> u64 {
        // `0x05` is one address across all pricings, so composition replaces rather than adds.
        let address = ModExp::<Berlin, AuroraModExp>::ADDRESS.raw();
        let context = aurora_engine_precompiles::Context {
            address,
            caller: H160::zero(),
            apparent_value: U256::zero(),
        };
        set.0[&address]
            .run(&TRIVIAL_MODEXP, Some(EthGas::new(100_000)), &context, false)
            .unwrap()
            .cost
            .as_u64()
    }

    #[test]
    fn kzg_activation_starts_at_cancun() {
        assert!(!Precompiles::new(&Spec::Shanghai).is_precompile(Kzg::ADDRESS));
        for spec in [Spec::Cancun, Spec::Prague, Spec::Osaka] {
            assert!(Precompiles::new(&spec).is_precompile(Kzg::ADDRESS));
        }
    }

    /// Each fork adds exactly its own addresses — a superset check would miss a stray entry.
    #[test]
    fn each_fork_adds_exactly_its_own_addresses() {
        let istanbul = addresses(&Precompiles::new_istanbul());
        let berlin = addresses(&Precompiles::new_berlin());
        let cancun = addresses(&Precompiles::new_cancun());
        let prague = addresses(&Precompiles::new_prague());
        let osaka = addresses(&Precompiles::new_osaka());

        // Berlin only reprices `0x05`, so the address set is unchanged.
        assert_eq!(berlin, istanbul);
        assert_eq!(
            cancun.difference(&berlin).copied().collect::<Vec<_>>(),
            vec![Kzg::ADDRESS]
        );
        assert_eq!(
            prague.difference(&cancun).copied().collect::<Vec<_>>(),
            vec![
                BlsG1Add::ADDRESS.raw(),
                BlsG1Msm::ADDRESS.raw(),
                BlsG2Add::ADDRESS.raw(),
                BlsG2Msm::ADDRESS.raw(),
                BlsPairingCheck::ADDRESS.raw(),
                BlsMapFpToG1::ADDRESS.raw(),
                BlsMapFp2ToG2::ADDRESS.raw(),
            ]
        );
        assert_eq!(
            osaka.difference(&prague).copied().collect::<Vec<_>>(),
            vec![Secp256r1::ADDRESS.raw()]
        );
        assert_eq!(
            [
                istanbul.len(),
                berlin.len(),
                cancun.len(),
                prague.len(),
                osaka.len()
            ],
            [9, 9, 10, 17, 18]
        );
    }

    /// The repricings are invisible to the address set, so they are pinned by cost: EIP-198 charges
    /// nothing at the floor, EIP-2565 charges 200, EIP-7883 charges 500.
    #[test]
    fn modexp_is_repriced_at_berlin_and_osaka() {
        assert_eq!(modexp_cost(&Precompiles::new_istanbul()), 0);
        assert_eq!(modexp_cost(&Precompiles::new_berlin()), 200);
        assert_eq!(modexp_cost(&Precompiles::new_cancun()), 200);
        assert_eq!(modexp_cost(&Precompiles::new_prague()), 200);
        assert_eq!(modexp_cost(&Precompiles::new_osaka()), 500);
    }
}
