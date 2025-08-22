use crate::types::Spec;
use aurora_evm::executor::stack::{PrecompileFailure, PrecompileFn, PrecompileOutput};
use aurora_evm::utils::U64_MAX;
use aurora_evm::{Context, ExitError, ExitSucceed};
use ethjson::hash::Address;
use ethjson::spec::builtin::{
    AltBn128ConstOperations, AltBn128Pairing, BuiltinCompat, PricingAt, PricingCompat,
};
use ethjson::spec::{ForkSpec, Linear, Pricing};
use ethjson::uint::Uint;
use primitive_types::{H160, U256};
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Debug, Clone)]
struct Precompile;

type LazyPrecompiles = LazyLock<BTreeMap<H160, ethcore_builtin::Builtin>>;
static ISTANBUL_BUILTINS: LazyPrecompiles = LazyLock::new(istanbul_builtins);
static BERLIN_BUILTINS: LazyPrecompiles = LazyLock::new(berlin_builtins);
static CANCUN_BUILTINS: LazyPrecompiles = LazyLock::new(cancun_builtins);
static PRAGUE_BUILTINS: LazyPrecompiles = LazyLock::new(prague_builtins);

macro_rules! precompile_entry {
    ($map:expr, $builtins:expr, $index:expr) => {
        let x: PrecompileFn =
            |input: &[u8], gas_limit: Option<u64>, _context: &Context, _is_static: bool| {
                let builtin = $builtins.get(&H160::from_low_u64_be($index)).unwrap();
                Self::exec_as_precompile(builtin, input, gas_limit)
            };
        $map.insert(H160::from_low_u64_be($index), x);
    };
}

pub struct JsonPrecompile;

impl JsonPrecompile {
    #[allow(clippy::match_same_arms)]
    pub fn precompile(spec: &Spec) -> Option<BTreeMap<H160, PrecompileFn>> {
        match spec {
            Spec::Istanbul => {
                let mut map = BTreeMap::new();
                precompile_entry!(map, ISTANBUL_BUILTINS, 1);
                precompile_entry!(map, ISTANBUL_BUILTINS, 2);
                precompile_entry!(map, ISTANBUL_BUILTINS, 3);
                precompile_entry!(map, ISTANBUL_BUILTINS, 4);
                precompile_entry!(map, ISTANBUL_BUILTINS, 5);
                precompile_entry!(map, ISTANBUL_BUILTINS, 6);
                precompile_entry!(map, ISTANBUL_BUILTINS, 7);
                precompile_entry!(map, ISTANBUL_BUILTINS, 8);
                precompile_entry!(map, ISTANBUL_BUILTINS, 9);
                Some(map)
            }
            Spec::Berlin => {
                let mut map = BTreeMap::new();
                precompile_entry!(map, BERLIN_BUILTINS, 1);
                precompile_entry!(map, BERLIN_BUILTINS, 2);
                precompile_entry!(map, BERLIN_BUILTINS, 3);
                precompile_entry!(map, BERLIN_BUILTINS, 4);
                precompile_entry!(map, BERLIN_BUILTINS, 5);
                precompile_entry!(map, BERLIN_BUILTINS, 6);
                precompile_entry!(map, BERLIN_BUILTINS, 7);
                precompile_entry!(map, BERLIN_BUILTINS, 8);
                precompile_entry!(map, BERLIN_BUILTINS, 9);
                Some(map)
            }
            // precompiles for London and Berlin are the same
            Spec::London => Self::precompile(&Spec::Berlin),
            // precompiles for Merge and Berlin are the same
            Spec::Merge => Self::precompile(&Spec::Berlin),
            // precompiles for Shanghai and Berlin are the same
            Spec::Shanghai => Self::precompile(&Spec::Berlin),
            Spec::Cancun => {
                let mut map = BTreeMap::new();
                precompile_entry!(map, CANCUN_BUILTINS, 1);
                precompile_entry!(map, CANCUN_BUILTINS, 2);
                precompile_entry!(map, CANCUN_BUILTINS, 3);
                precompile_entry!(map, CANCUN_BUILTINS, 4);
                precompile_entry!(map, CANCUN_BUILTINS, 5);
                precompile_entry!(map, CANCUN_BUILTINS, 6);
                precompile_entry!(map, CANCUN_BUILTINS, 7);
                precompile_entry!(map, CANCUN_BUILTINS, 8);
                precompile_entry!(map, CANCUN_BUILTINS, 9);
                precompile_entry!(map, CANCUN_BUILTINS, 0xA);
                Some(map)
            }
            Spec::Prague => {
                let mut map = BTreeMap::new();
                precompile_entry!(map, PRAGUE_BUILTINS, 1);
                precompile_entry!(map, PRAGUE_BUILTINS, 2);
                precompile_entry!(map, PRAGUE_BUILTINS, 3);
                precompile_entry!(map, PRAGUE_BUILTINS, 4);
                precompile_entry!(map, PRAGUE_BUILTINS, 5);
                precompile_entry!(map, PRAGUE_BUILTINS, 6);
                precompile_entry!(map, PRAGUE_BUILTINS, 7);
                precompile_entry!(map, PRAGUE_BUILTINS, 8);
                precompile_entry!(map, PRAGUE_BUILTINS, 9);
                precompile_entry!(map, PRAGUE_BUILTINS, 0x0A);
                precompile_entry!(map, PRAGUE_BUILTINS, 0x0B);
                precompile_entry!(map, PRAGUE_BUILTINS, 0x0C);
                precompile_entry!(map, PRAGUE_BUILTINS, 0x0D);
                precompile_entry!(map, PRAGUE_BUILTINS, 0x0E);
                precompile_entry!(map, PRAGUE_BUILTINS, 0x0F);
                precompile_entry!(map, PRAGUE_BUILTINS, 0x10);
                precompile_entry!(map, PRAGUE_BUILTINS, 0x11);
                Some(map)
            }
            _ => None,
        }
    }

    fn exec_as_precompile(
        builtin: &ethcore_builtin::Builtin,
        input: &[u8],
        gas_limit: Option<u64>,
    ) -> Result<(PrecompileOutput, u64), PrecompileFailure> {
        let cost = builtin.cost(input, 0);

        if let Some(target_gas) = gas_limit {
            if cost > U64_MAX || target_gas < cost.as_u64() {
                return Err(PrecompileFailure::Error {
                    exit_status: ExitError::OutOfGas,
                });
            }
        }

        let mut output = Vec::new();
        match builtin.execute(input, &mut parity_bytes::BytesRef::Flexible(&mut output)) {
            Ok(()) => Ok((
                PrecompileOutput {
                    exit_status: ExitSucceed::Stopped,
                    output,
                },
                cost.as_u64(),
            )),
            Err(e) => Err(PrecompileFailure::Error {
                exit_status: ExitError::Other(e.into()),
            }),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn istanbul_builtins() -> BTreeMap<H160, ethcore_builtin::Builtin> {
    use ethjson::spec::builtin::{BuiltinCompat, Linear, Modexp, PricingCompat};

    let builtins: BTreeMap<Address, BuiltinCompat> = BTreeMap::from([
        (
            Address(H160::from_low_u64_be(1)),
            BuiltinCompat {
                name: "ecrecover".to_string(),
                pricing: PricingCompat::Single(Pricing::Linear(Linear {
                    base: 3000,
                    word: 0,
                })),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(2)),
            BuiltinCompat {
                name: "sha256".to_string(),
                pricing: PricingCompat::Single(Pricing::Linear(Linear { base: 60, word: 12 })),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(3)),
            BuiltinCompat {
                name: "ripemd160".to_string(),
                pricing: PricingCompat::Single(Pricing::Linear(Linear {
                    base: 600,
                    word: 120,
                })),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(4)),
            BuiltinCompat {
                name: "identity".to_string(),
                pricing: PricingCompat::Single(Pricing::Linear(Linear { base: 15, word: 3 })),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(5)),
            BuiltinCompat {
                name: "modexp".to_string(),
                pricing: PricingCompat::Single(Pricing::Modexp(Modexp {
                    divisor: 20,
                    is_eip_2565: false,
                })),
                activate_at: Some(Uint(U256::zero())),
            },
        ),
        (
            Address(H160::from_low_u64_be(6)),
            BuiltinCompat {
                name: "alt_bn128_add".to_string(),
                pricing: PricingCompat::Multi(BTreeMap::from([(
                    Uint(U256::zero()),
                    PricingAt {
                        info: Some("EIP 1108 transition".to_string()),
                        price: Pricing::AltBn128ConstOperations(AltBn128ConstOperations {
                            price: 150,
                        }),
                    },
                )])),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(7)),
            BuiltinCompat {
                name: "alt_bn128_mul".to_string(),
                pricing: PricingCompat::Multi(BTreeMap::from([(
                    Uint(U256::zero()),
                    PricingAt {
                        info: Some("EIP 1108 transition".to_string()),
                        price: Pricing::AltBn128ConstOperations(AltBn128ConstOperations {
                            price: 6000,
                        }),
                    },
                )])),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(8)),
            BuiltinCompat {
                name: "alt_bn128_pairing".to_string(),
                pricing: PricingCompat::Multi(BTreeMap::from([(
                    Uint(U256::zero()),
                    PricingAt {
                        info: Some("EIP 1108 transition".to_string()),
                        price: Pricing::AltBn128Pairing(AltBn128Pairing {
                            base: 45000,
                            pair: 34000,
                        }),
                    },
                )])),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(9)),
            BuiltinCompat {
                name: "blake2_f".to_string(),
                pricing: PricingCompat::Single(Pricing::Blake2F { gas_per_round: 1 }),
                activate_at: Some(Uint(U256::zero())),
            },
        ),
    ]);
    builtins
        .into_iter()
        .map(|(address, builtin)| {
            (
                address.into(),
                ethjson::spec::Builtin::from(builtin).try_into().unwrap(),
            )
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn berlin_builtins() -> BTreeMap<H160, ethcore_builtin::Builtin> {
    use ethjson::spec::builtin::{BuiltinCompat, Linear, Modexp, PricingCompat};

    let builtins: BTreeMap<Address, BuiltinCompat> = BTreeMap::from([
        (
            Address(H160::from_low_u64_be(1)),
            BuiltinCompat {
                name: "ecrecover".to_string(),
                pricing: PricingCompat::Single(Pricing::Linear(Linear {
                    base: 3000,
                    word: 0,
                })),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(2)),
            BuiltinCompat {
                name: "sha256".to_string(),
                pricing: PricingCompat::Single(Pricing::Linear(Linear { base: 60, word: 12 })),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(3)),
            BuiltinCompat {
                name: "ripemd160".to_string(),
                pricing: PricingCompat::Single(Pricing::Linear(Linear {
                    base: 600,
                    word: 120,
                })),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(4)),
            BuiltinCompat {
                name: "identity".to_string(),
                pricing: PricingCompat::Single(Pricing::Linear(Linear { base: 15, word: 3 })),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(5)),
            BuiltinCompat {
                name: "modexp".to_string(),
                pricing: PricingCompat::Single(Pricing::Modexp(Modexp {
                    divisor: 3,
                    is_eip_2565: true,
                })),
                activate_at: Some(Uint(U256::zero())),
            },
        ),
        (
            Address(H160::from_low_u64_be(6)),
            BuiltinCompat {
                name: "alt_bn128_add".to_string(),
                pricing: PricingCompat::Multi(BTreeMap::from([(
                    Uint(U256::zero()),
                    PricingAt {
                        info: Some("EIP 1108 transition".to_string()),
                        price: Pricing::AltBn128ConstOperations(AltBn128ConstOperations {
                            price: 150,
                        }),
                    },
                )])),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(7)),
            BuiltinCompat {
                name: "alt_bn128_mul".to_string(),
                pricing: PricingCompat::Multi(BTreeMap::from([(
                    Uint(U256::zero()),
                    PricingAt {
                        info: Some("EIP 1108 transition".to_string()),
                        price: Pricing::AltBn128ConstOperations(AltBn128ConstOperations {
                            price: 6000,
                        }),
                    },
                )])),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(8)),
            BuiltinCompat {
                name: "alt_bn128_pairing".to_string(),
                pricing: PricingCompat::Multi(BTreeMap::from([(
                    Uint(U256::zero()),
                    PricingAt {
                        info: Some("EIP 1108 transition".to_string()),
                        price: Pricing::AltBn128Pairing(AltBn128Pairing {
                            base: 45000,
                            pair: 34000,
                        }),
                    },
                )])),
                activate_at: None,
            },
        ),
        (
            Address(H160::from_low_u64_be(9)),
            BuiltinCompat {
                name: "blake2_f".to_string(),
                pricing: PricingCompat::Single(Pricing::Blake2F { gas_per_round: 1 }),
                activate_at: Some(Uint(U256::zero())),
            },
        ),
    ]);
    builtins
        .into_iter()
        .map(|(address, builtin)| {
            (
                address.into(),
                ethjson::spec::Builtin::from(builtin).try_into().unwrap(),
            )
        })
        .collect()
}

fn cancun_builtins() -> BTreeMap<H160, ethcore_builtin::Builtin> {
    use ethjson::spec::builtin::{BuiltinCompat, Linear, PricingCompat};

    let mut builtins = berlin_builtins();
    builtins.insert(
        Address(H160::from_low_u64_be(0xA)).into(),
        ethjson::spec::Builtin::from(BuiltinCompat {
            name: "kzg".to_string(),
            pricing: PricingCompat::Single(Pricing::Linear(Linear {
                base: 50_000,
                word: 0,
            })),
            activate_at: None,
        })
        .try_into()
        .unwrap(),
    );
    builtins
}

fn prague_builtins() -> BTreeMap<H160, ethcore_builtin::Builtin> {
    use ethjson::spec::builtin::{BuiltinCompat, Linear, PricingCompat};

    let mut builtins = cancun_builtins();
    builtins.insert(
        Address(H160::from_low_u64_be(0xB)).into(),
        ethjson::spec::Builtin::from(BuiltinCompat {
            name: "bls12_381_g1_add".to_string(),
            pricing: PricingCompat::Single(Pricing::Linear(Linear { base: 375, word: 0 })),
            activate_at: None,
        })
        .try_into()
        .unwrap(),
    );
    builtins.insert(
        Address(H160::from_low_u64_be(0xC)).into(),
        ethjson::spec::Builtin::from(BuiltinCompat {
            name: "bls12_381_g1_mul".to_string(),
            pricing: PricingCompat::Single(Pricing::Bls12G1Mul),
            activate_at: None,
        })
        .try_into()
        .unwrap(),
    );
    builtins.insert(
        Address(H160::from_low_u64_be(0xD)).into(),
        ethjson::spec::Builtin::from(BuiltinCompat {
            name: "bls12_381_g2_add".to_string(),
            pricing: PricingCompat::Single(Pricing::Linear(Linear { base: 600, word: 0 })),
            activate_at: None,
        })
        .try_into()
        .unwrap(),
    );
    builtins.insert(
        Address(H160::from_low_u64_be(0xE)).into(),
        ethjson::spec::Builtin::from(BuiltinCompat {
            name: "bls12_381_g2_mul".to_string(),
            pricing: PricingCompat::Single(Pricing::Bls12G2Mul),
            activate_at: None,
        })
        .try_into()
        .unwrap(),
    );
    builtins.insert(
        Address(H160::from_low_u64_be(0xF)).into(),
        ethjson::spec::Builtin::from(BuiltinCompat {
            name: "bls12_381_pairing".to_string(),
            pricing: PricingCompat::Single(Pricing::Bls12Pairing),
            activate_at: None,
        })
        .try_into()
        .unwrap(),
    );
    builtins.insert(
        Address(H160::from_low_u64_be(0x10)).into(),
        ethjson::spec::Builtin::from(BuiltinCompat {
            name: "bls12_381_fp_to_g1".to_string(),
            pricing: PricingCompat::Single(Pricing::Linear(Linear {
                base: 5_500,
                word: 0,
            })),
            activate_at: None,
        })
        .try_into()
        .unwrap(),
    );
    builtins.insert(
        Address(H160::from_low_u64_be(0x11)).into(),
        ethjson::spec::Builtin::from(BuiltinCompat {
            name: "bls12_381_fp2_to_g2".to_string(),
            pricing: PricingCompat::Single(Pricing::Linear(Linear {
                base: 23_800,
                word: 0,
            })),
            activate_at: None,
        })
        .try_into()
        .unwrap(),
    );

    builtins
}
