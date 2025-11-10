mod kzg;

use crate::precompiles::kzg::Kzg;
use crate::types::Spec;
use aurora_engine_modexp::AuroraModExp;
use aurora_engine_precompiles::{
    alt_bn256::{Bn256Add, Bn256Mul, Bn256Pair},
    blake2::Blake2F,
    hash::{RIPEMD160, SHA256},
    identity::Identity,
    modexp::ModExp,
    secp256k1::ECRecover,
    Berlin, Byzantium, EthGas, Istanbul, Precompile,
};
use aurora_evm::executor::stack::{
    PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileSet,
};
use aurora_evm::{ExitError, ExitSucceed, Opcode};
use primitive_types::H160;
use std::collections::BTreeMap;

pub struct Precompiles(BTreeMap<H160, Box<dyn Precompile>>);

impl PrecompileSet for Precompiles {
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<PrecompileOutput, PrecompileFailure>> {
        let p = self.0.get(&handle.code_address())?;
        let result = process_precompile(p.as_ref(), handle);
        Some(result.and_then(|output| post_process(output, handle)))
    }

    fn is_precompile(&self, address: H160) -> bool {
        self.0.contains_key(&address)
    }
}

impl Precompiles {
    pub fn new(spec: &Spec) -> Self {
        match *spec {
            Spec::Frontier
            | Spec::Homestead
            | Spec::Tangerine
            | Spec::SpuriousDragon
            | Spec::Byzantium
            | Spec::Constantinople
            | Spec::Petersburg
            | Spec::Istanbul => Self::new_istanbul(),
            Spec::Berlin | Spec::London | Spec::Merge | Spec::Shanghai => Self::new_berlin(),
            Spec::Cancun => Self::new_cancun(),
            Spec::Prague | Spec::Osaka => Self::new_prague(),
        }
    }

    pub fn new_istanbul() -> Self {
        let mut map = BTreeMap::new();
        map.insert(
            ECRecover::ADDRESS.raw(),
            Box::new(ECRecover) as Box<dyn Precompile>,
        );
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

    pub fn new_berlin() -> Self {
        let mut map = BTreeMap::new();
        map.insert(
            ECRecover::ADDRESS.raw(),
            Box::new(ECRecover) as Box<dyn Precompile>,
        );
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

    pub fn new_cancun() -> Self {
        let mut map = Self::new_berlin().0;
        map.insert(Kzg::ADDRESS, Box::new(Kzg));
        Self(map)
    }

    pub fn new_prague() -> Self {
        let map = Self::new_cancun().0;
        Self(map)
    }
}

fn process_precompile(
    p: &dyn Precompile,
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

    p.run(input, gas_limit.map(EthGas::new), &context, is_static)
        .map_err(|err| PrecompileFailure::Error {
            exit_status: get_exit_error(err),
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

fn get_exit_error(exit_error: aurora_engine_precompiles::ExitError) -> ExitError {
    match exit_error {
        aurora_engine_precompiles::ExitError::StackUnderflow => ExitError::StackUnderflow,
        aurora_engine_precompiles::ExitError::StackOverflow => ExitError::StackOverflow,
        aurora_engine_precompiles::ExitError::InvalidJump => ExitError::InvalidJump,
        aurora_engine_precompiles::ExitError::InvalidRange => ExitError::InvalidRange,
        aurora_engine_precompiles::ExitError::DesignatedInvalid => ExitError::DesignatedInvalid,
        aurora_engine_precompiles::ExitError::CallTooDeep => ExitError::CallTooDeep,
        aurora_engine_precompiles::ExitError::CreateCollision => ExitError::CreateCollision,
        aurora_engine_precompiles::ExitError::CreateContractLimit => ExitError::CreateContractLimit,
        aurora_engine_precompiles::ExitError::InvalidCode(op) => {
            ExitError::InvalidCode(Opcode(op.0))
        }
        aurora_engine_precompiles::ExitError::OutOfOffset => ExitError::OutOfOffset,
        aurora_engine_precompiles::ExitError::OutOfGas => ExitError::OutOfGas,
        aurora_engine_precompiles::ExitError::OutOfFund => ExitError::OutOfFund,
        aurora_engine_precompiles::ExitError::PCUnderflow => ExitError::PCUnderflow,
        aurora_engine_precompiles::ExitError::CreateEmpty => ExitError::CreateEmpty,
        aurora_engine_precompiles::ExitError::Other(msg) => ExitError::Other(msg),
        aurora_engine_precompiles::ExitError::MaxNonce => ExitError::MaxNonce,
        aurora_engine_precompiles::ExitError::UsizeOverflow => ExitError::UsizeOverflow,
        aurora_engine_precompiles::ExitError::CreateContractStartingWithEF => {
            ExitError::CreateContractStartingWithEF
        }
    }
}
