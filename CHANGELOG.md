# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-09-03
> **Osaka Hard Fork Release**
>
> The primary purpose of this release is support for the **Osaka** hard fork.
>
> **Scope**: Osaka support here covers **EIP-7939** (`CLZ`) in the EVM core and the
> **EIP-7823** / **EIP-7883** `MODEXP` repricing in the test precompile set. The remaining
> Osaka EIPs are not implemented yet — notably **EIP-7825** (transaction gas limit cap),
> **EIP-7907** (contract code size limit) and **EIP-7951** (`P256VERIFY` precompile).
>
> **History**: the Osaka work [[#99]] branched off `v2.2.0` and landed on the mainline
> *before* the `v2.2.1` gasometer line, which was merged afterwards via [[#104]].
> Consequently **`v3.0.0` contains every change of `v2.2.1`**, even though Osaka carries a
> lower pull request number.

### Added
- **Osaka Hard Fork Support** [[#99]]:
  - Added the `Config::osaka()` configuration — Prague plus the new `has_clz` flag.
  - **EIP-7939**: Implemented the `CLZ` (Count Leading Zeros) opcode `0x1E`, priced at `G_low` (5 gas), with unit tests. For pre-Osaka configurations the opcode is rejected with `ExitError::InvalidCode`.
  - Added the Osaka precompile set to the test runner, which activates the `MODEXP` rules of **EIP-7823** (input size bounds) and **EIP-7883** (increased gas cost).
- **System calls**: Added `StackExecutor::system_call` to execute the protocol-level calls required by **EIP-4788**, **EIP-2935**, **EIP-7002** and **EIP-7251** [[#111]].
  - The caller is supplied by the host, which is expected to pass the protocol-defined `SYSTEM_ADDRESS`; the executor does not enforce it.
  - The call carries zero value and performs no transfer, so the caller balance is not checked, the nonce is not incremented, no base transaction cost is recorded, and the context is not static. The gas limit is inherited from the executor's `StackSubstateMetadata` — per the EIPs the host must construct the executor with `30_000_000` gas.
- Extended the `with-serde` feature: `Authorization` now derives `serde::Serialize` and `serde::Deserialize` [[#106]].
- Enabled **Osaka** state test coverage by moving the CI fixtures to `execution-spec-tests` **v5.4.0** [[#105]].
- Added transaction validation reasons to the test suite: `AccessListNotSupported` and `AuthorizationListNotSupportedForCreate` [[#105]].
- Added new CLI options to the `state` subcommand of `aurora-evm-jsontests` [[#108]]:
  - `--dump_successful_tx <FILE_NAME>` — dumps every executed and applied transaction to a JSON file.
  - `--slow_tests` — prints a benchmark report of the slowest tests.
- Added unit tests covering the account `is_empty` logic against both the substate cache and the backend [[#110]].
- Added this `CHANGELOG.md` [[#107]].

### Changed
- Merged the **v2.2.1** gasometer refactoring line into the mainline, together with a comment typo fix [[#104]]. See the `2.2.1` section below for its contents.
- **Toolchain**: Pinned Rust to **1.97.0** in `rust-toolchain.toml`, up from 1.86.0 [[#115]].
  - **Breaking**: building the workspace now requires Rust 1.97.0. No `rust-version` key is declared, so the minimum version is not enforced by Cargo.
  - Moved the `rust` and `clippy` lint configuration into `[workspace.lints]` — out of the crate-level attributes in `evm/src/lib.rs` and out of the `[lints.clippy]` block of `evm-tests/Cargo.toml` — and simplified the CI clippy invocations accordingly.
- **Breaking**: `Config` gained the public field `has_clz`; code constructing `Config` with a struct literal must be updated [[#99]].
- Replaced the git dependencies `aurora-engine-modexp` and `aurora-engine-precompiles` (tag `3.10.0-rc.1`) with the published `aurora-engine-precompiles` **2.1.0** crate in the test suite [[#99]].
- The test suite now derives intrinsic gas and the EIP-7623 gas floor from `Gasometer::calculate_intrinsic_gas_and_gas_floor` instead of its own implementation [[#105]].
- Consolidated the CI test fixtures into that single **v5.4.0** stable bundle, replacing the former `pectra-devnet-6@v1.0.0`, `v4.5.0` stable and `v4.5.0` static bundles [[#105]].
- Refactored the `MemoryStackSubstate` lookups (`known_account`, `deleted`, `is_created`, `recursive_is_cold`) into flatter combinator form and added doc comments to its public accessors [[#109]].
- `aurora-evm-jsontests` now depends on `aurora-evm` with the `with-serde` feature enabled [[#108]].
- Simplified path handling and test skipping in the test runner [[#102]].
- Corrected doc comments to use angle-bracketed intra-doc URLs, and applied assorted clippy-driven cleanups [[#115]].

### Removed
- **Breaking**: Removed `MemoryStackSubstate::known_empty`; the emptiness logic now lives entirely in `MemoryStackState::is_empty` [[#110]].
- Removed the test suite EIP-7623 helper module `types::eip_7623` in favour of the gasometer API [[#105]].

### Fixed
- **Account emptiness check** (EIP-161 state clearing): for an account already cached in the substate, `MemoryStackState::is_empty` now reads `balance` and `nonce` from that cache and consults the backend only for the account code [[#110]].
  Previously, a cached account with zero balance and nonce but without cached code made the whole check fall through to the backend, so balance and nonce changes performed during execution were discarded and account emptiness could be reported incorrectly. On that fall-through path `Backend::basic` was also queried twice; it is now queried once.
- Transaction validation in the test suite now rejects a type-4 (`TxType::EOAAccountCode`, EIP-7702) transaction used for contract creation, and a type-1 (access list) transaction before Berlin [[#105]].
- Accepted the `execution-spec-tests` v5.4.0 exception names `TransactionException.TYPE_1_TX_PRE_FORK`, `TransactionException.TYPE_2_TX_PRE_FORK`, `TransactionException.TYPE_4_TX_PRE_FORK`, `TransactionException.INTRINSIC_GAS_BELOW_FLOOR_GAS_COST` and the composite `TransactionException.INTRINSIC_GAS_TOO_LOW|TransactionException.INTRINSIC_GAS_BELOW_FLOOR_GAS_COST` [[#105]].

## [2.2.1] - 2026-01-23
### Added
- Utilities for consolidated gas calculation and verification: `intrinsic_gas_and_gas_floor` and `calculate_intrinsic_gas_and_gas_floor` [[#100]].

### Changed
- **Gasometer Refactoring**: Major refactoring of the `gasometer` module to improve transaction processing consistency [[#100]].
- Improved transaction verification: Implemented enforced checks for gas limits and the "gas floor" threshold according to EIP-7623.
- Optimized gas calculation logic, reducing code redundancy between contract call and creation paths.

### Fixed
- Fixed `floor gas` calculation for EIP-7623: Replaced the configurable value with the fixed constant `21000`, as required by the protocol specification [[#100]].

## [2.2.0] - 2026-01-07
### Added
- Added support for **Prague** and **Osaka** hard forks in the test suite [[#95]].
- Added support for new EIPs in tests:
  - **EIP-4844**: Blob pricing.
  - **EIP-7623**: Calldata cost.
  - **EIP-7702**: Authorization.
- Implemented a precompile for KZG blob verification in the test environment.
- Added state dump functionality (`dump-state`) for debugging purposes.

### Changed
- **Global Test Refactoring**: Completely restructured `aurora-evm-tests` (formerly `jsontests`) [[#95]].
- Renamed the package to `aurora-evm-jsontests`.
- Removed obsolete crates `ethjson` and `ethcore-builtin`.
- Reworked `test-runner`: Implemented config-based setup, test filtering, and improved reporting.
- Updated Rust toolchain to version 1.86.0 for tests.

### Removed
- Removed code associated with the `GPL-3.0` license.
- Removed legacy specification parsing code and old EVM test helpers.

## [2.1.3] - 2025-07-12
### Changed
- **Toolchain Downgrade**: Downgraded Rust version from 1.87.0 to 1.81.0 to ensure compatibility [[#96]].
- Removed `const` qualifiers from several methods (`state_mut`, `gasometer_mut`, `stack_mut`, `memory_mut`) to support older Rust versions.
- Replaced the unstable `is_none_or` method with standard `Option::map_or` in storage and buffer verification logic.

## [2.1.2] - 2025-06-11
### Fixed
- **Gas Cost Fixes**: Fixed and refactored gas calculation for `EXT-*` and `BALANCE` opcodes in scenarios without delegated gas computation [[#94]].
- Resolved potential inconsistency in "cold" and "hot" address access logic that arose after extracting the gas module.

### Changed
- Added clippy allowances for `const fn` to support compatibility with `Rust v1.86`.

## [2.1.1] - 2025-06-06
### Changed
- Updated Rust toolchain to version **1.87** [[#93]].
- Updated Rust toolchain to version **1.86** [[#89]].

### Added
- Updated `execution-spec-tests` suite:
  - Added version **v4.5.0** (Hradčany) [[#92]].
  - Added version **v4.4.0** (Stromovka) [[#90]].
  - Added version **v4.3.0** (Vltava) [[#88]].

## [2.1.0] - 2025-04-21
### Performance
- **Optimizations**:
  - Optimized `CALLDATALOAD` opcode execution [[#87]].
  - Implemented memory operation optimizations (replaced loops with `copy_from_slice`).
  - **Result**: NEAR gas consumption reduced by approximately **3%**.

### Changed
- Code Refactoring: Added `ZERO` and `ONE` constants for the `U256` type to simplify the codebase [[#87]].
- Updated `ethereum/tests` suite to version **v17.0** [[#86]].
- Improved error messages in tests (added filenames to assertions).
- Split CI into separate workflows for the linter and eth-tests.

## [2.0.0] - 2025-03-26
### Added
- **Prague Hard Fork Support**: Full implementation of the Prague hard fork [[#67]].
  - **EIP-7702**: Implemented "Set Code Account" (EOA code delegation).
  - **EIP-7623**: Increased calldata cost to reduce block size.
  - **EIP-2537**: Added precompiles for BLS12-381 curve operations.
  - **EIP-4399**: Supplant DIFFICULTY opcode with PREVRANDAO.
  - **EIP-7069**: Revamped CALL instructions.
- Added comprehensive tests for all new EIPs [[#85]].

### Changed
- Consolidated EVM crate structure and standardized error handling [[#81]].
- Updated internal dependencies and module visibility for the major release [[#74]].

## [1.0.0] - 2025-03-21
> **First Major Release** by @mrLSD

This release marks the final transformation of the project from a SputnikVM fork into the standalone **Aurora EVM** product.

### Added
- **Cancun Hard Fork**: Full support for Cancun hard fork functionality.
- **New Architecture**: Consolidated the project into a single `aurora-evm` crate, eliminating the fragmentation of the original SputnikVM.
- **Test Coverage**: Achieved **100% test coverage** using `ethereum/tests` and `ethereum/execution-spec-tests` suites.

### Performance
- Implemented significant performance optimizations.
- **Result**: NEAR gas consumption reduced by **at least 2x** compared to the original SputnikVM (based on Aurora Engine benchmarks).

### Changed
- Complete codebase refactoring to improve readability and maintainability.
- Redesigned module structure.

[//]: # (Link Definitions)

[3.0.0]: https://github.com/aurora-is-near/aurora-evm/compare/v2.2.1...v3.0.0
[2.2.1]: https://github.com/aurora-is-near/aurora-evm/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/aurora-is-near/aurora-evm/compare/v2.1.3...v2.2.0
[2.1.3]: https://github.com/aurora-is-near/aurora-evm/compare/v2.1.2...v2.1.3
[2.1.2]: https://github.com/aurora-is-near/aurora-evm/compare/v2.1.1...v2.1.2
[2.1.1]: https://github.com/aurora-is-near/aurora-evm/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/aurora-is-near/aurora-evm/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/aurora-is-near/aurora-evm/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/aurora-is-near/aurora-evm/releases/tag/v1.0.0

[#115]: https://github.com/aurora-is-near/aurora-evm/pull/115
[#111]: https://github.com/aurora-is-near/aurora-evm/pull/111
[#110]: https://github.com/aurora-is-near/aurora-evm/pull/110
[#109]: https://github.com/aurora-is-near/aurora-evm/pull/109
[#108]: https://github.com/aurora-is-near/aurora-evm/pull/108
[#107]: https://github.com/aurora-is-near/aurora-evm/pull/107
[#106]: https://github.com/aurora-is-near/aurora-evm/pull/106
[#105]: https://github.com/aurora-is-near/aurora-evm/pull/105
[#104]: https://github.com/aurora-is-near/aurora-evm/pull/104
[#102]: https://github.com/aurora-is-near/aurora-evm/pull/102
[#100]: https://github.com/aurora-is-near/aurora-evm/pull/100
[#99]: https://github.com/aurora-is-near/aurora-evm/pull/99
[#96]: https://github.com/aurora-is-near/aurora-evm/pull/96
[#95]: https://github.com/aurora-is-near/aurora-evm/pull/95
[#94]: https://github.com/aurora-is-near/aurora-evm/pull/94
[#93]: https://github.com/aurora-is-near/aurora-evm/pull/93
[#92]: https://github.com/aurora-is-near/aurora-evm/pull/92
[#90]: https://github.com/aurora-is-near/aurora-evm/pull/90
[#89]: https://github.com/aurora-is-near/aurora-evm/pull/89
[#88]: https://github.com/aurora-is-near/aurora-evm/pull/88
[#87]: https://github.com/aurora-is-near/aurora-evm/pull/87
[#86]: https://github.com/aurora-is-near/aurora-evm/pull/86
[#85]: https://github.com/aurora-is-near/aurora-evm/pull/85
[#81]: https://github.com/aurora-is-near/aurora-evm/pull/81
[#74]: https://github.com/aurora-is-near/aurora-evm/pull/74
[#67]: https://github.com/aurora-is-near/aurora-evm/pull/67