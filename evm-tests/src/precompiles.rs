// mod kzg;

// use crate::precompiles::kzg::Kzg;
use crate::types::Spec;
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
    Berlin, Byzantium, EthGas, Istanbul, Osaka, Precompile,
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
            Spec::Prague => Self::new_prague(),
            Spec::Osaka => Self::new_osaka(),
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
        // map.insert(Kzg::ADDRESS, Box::new(Kzg));
        Self(map)
    }

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

    pub fn new_osaka() -> Self {
        let mut map = BTreeMap::new();
        map.insert(
            ECRecover::ADDRESS.raw(),
            Box::new(ECRecover) as Box<dyn Precompile>,
        );
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

        // map.insert(Kzg::ADDRESS, Box::new(Kzg));
        map.insert(BlsG1Add::ADDRESS.raw(), Box::new(BlsG1Add));
        map.insert(BlsG1Msm::ADDRESS.raw(), Box::new(BlsG1Msm));
        map.insert(BlsG2Add::ADDRESS.raw(), Box::new(BlsG2Add));
        map.insert(BlsG2Msm::ADDRESS.raw(), Box::new(BlsG2Msm));
        map.insert(BlsPairingCheck::ADDRESS.raw(), Box::new(BlsPairingCheck));
        map.insert(BlsMapFpToG1::ADDRESS.raw(), Box::new(BlsMapFpToG1));
        map.insert(BlsMapFp2ToG2::ADDRESS.raw(), Box::new(BlsMapFp2ToG2));
        Self(map)
    }
}

/// Precompile input and output data struct
#[cfg(feature = "dump-state")]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PrecompileStandaloneData {
    pub input: String,
    pub output: String,
}

/// Standalone data for the precompile tests.
/// It contains input data for precompile and expected
/// output after the precompile execution.
#[cfg(feature = "dump-state")]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PrecompileStandalone {
    pub precompile_data: Vec<PrecompileStandaloneData>,
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

    let output = p
        .run(input, gas_limit.map(EthGas::new), &context, is_static)
        .map_err(|err| PrecompileFailure::Error {
            exit_status: get_exit_error(err),
        });
    #[cfg(feature = "dump-state")]
    if let Ok(_out) = &output {
        /* EXAMPLE:
            dump_precompile_state(
                "bn256_pairing_all.json",
                input,
                &out.output,
                evm_context.address,
                Bn256Pair::<Istanbul>::ADDRESS.raw(),
            );
        */
    }

    output
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

/// Dumps precompile input and output data to a JSON file for test case generation.
///
/// It can be used for debugging and creating new test cases for precompiles.
#[cfg(feature = "dump-state")]
#[allow(dead_code)]
fn dump_precompile_state(
    file_name: &str,
    input: &[u8],
    output: &[u8],
    evm_context_address: H160,
    precompile_address: H160,
) {
    use std::fs;

    if input.is_empty() || evm_context_address != precompile_address {
        return;
    }

    let mut data = fs::read_to_string(file_name)
        .ok()
        .and_then(|content| {
            if content.trim().is_empty() {
                None
            } else {
                serde_json::from_str::<PrecompileStandalone>(&content).ok()
            }
        })
        .unwrap_or_else(|| PrecompileStandalone {
            precompile_data: Vec::new(),
        });

    let hex_input = hex::encode(input);
    let hex_output = hex::encode(output);

    if !data
        .precompile_data
        .iter()
        .any(|entry| entry.input == hex_input)
    {
        data.precompile_data.push(PrecompileStandaloneData {
            input: hex_input,
            output: hex_output,
        });

        if let Ok(serialized) = serde_json::to_string(&data) {
            fs::write(file_name, serialized).expect("Unable to write the file");
        } else {
            panic!("Unable to parse the file");
        }
    }
}
