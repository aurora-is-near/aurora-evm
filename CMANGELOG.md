# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2026-01-23

### Added

- Utilities for consolidated gas calculation and verification: `intrinsic_gas_and_gas_floor` and
  `calculate_intrinsic_gas_and_gas_floor` [#100].

### Changed

- **Gasometer Refactoring**: Major refactoring of the `gasometer` module to improve transaction processing
  consistency [#100].
- Improved transaction verification: Implemented enforced checks for gas limits and the "gas floor" threshold according
  to EIP-7623.
- Optimized gas calculation logic, reducing code redundancy between contract call and creation paths.

### Fixed

- Fixed `floor gas` calculation for EIP-7623: Replaced the configurable value with the fixed constant `21000`, as
  required by the protocol specification [#100].

## [2.2.0] - 2026-01-07

### Added

- Added support for **Prague** and **Osaka** Spec hard forks in the test suite [#95].
- Added support for new EIPs in tests:
    - **EIP-4844**: Blob pricing.
    - **EIP-7623**: Calldata cost.
    - **EIP-7702**: Authorization.
- Implemented a precompile for KZG blob verification in the test environment.
- Added state dump functionality (`dump-state`) for debugging purposes.

### Changed

- **Global Test Refactoring**: Completely restructured `aurora-evm-tests` (formerly `jsontests`) [#95].
- Renamed the package to `aurora-evm-jsontests`.
- Removed obsolete crates `ethjson` and `ethcore-builtin`.
- Reworked `test-runner`: Implemented config-based setup, test filtering, and improved reporting.
- Updated Rust toolchain to version 1.86.0 for tests.

### Removed

- Removed code associated with the `GPL-3.0` license.
- Removed legacy specification parsing code and old EVM test helpers.

## [2.1.3] - 2025-07-12

### Changed

- **Toolchain Downgrade**: Downgraded Rust version from 1.87.0 to 1.81.0 to ensure compatibility [#96].
- Removed `const` qualifiers from several methods (`state_mut`, `gasometer_mut`, `stack_mut`, `memory_mut`) to support
  older Rust versions.
- Replaced the unstable `is_none_or` method with standard `Option::map_or` in storage and buffer verification logic.

## [2.1.2] - 2025-06-11

### Fixed

- **Gas Cost Fixes**: Fixed and refactored gas calculation for `EXT-*` and `BALANCE` opcodes in scenarios without
  delegated gas computation [#94].
- Resolved potential inconsistency in "cold" and "hot" address access logic that arose after extracting the gas module.

### Changed

- Added clippy allowances for `const fn` to support compatibility with `Rust v1.86`.

## [2.1.1] - 2025-06-06

### Changed

- Updated Rust toolchain to version **1.87** [#93].
- Updated Rust toolchain to version **1.86** [#89].

### Added

- Updated `execution-spec-tests` suite:
    - Added version **v4.5.0** (Hradčany) [#92].
    - Added version **v4.4.0** (Stromovka) [#90].
    - Added version **v4.3.0** (Vltava) [#88].

## [2.1.0] - 2025-04-21

### Performance

- **Optimizations**:
    - Optimized `CALLDATALOAD` opcode execution [#87].
    - Implemented memory operation optimizations (replaced loops with `copy_from_slice`).
    - **Result**: NEAR gas consumption reduced by approximately **3%**.

### Changed

- Code Refactoring: Added `ZERO` and `ONE` constants for the `U256` type to simplify the codebase [#87].
- Updated `ethereum/tests` suite to version **v17.0** [#86].
- Improved error messages in tests (added filenames to assertions).
- Split CI into separate workflows for the linter and eth-tests.

## [2.0.0] - 2025-03-26

### Added

- **Prague Hard Fork Support**: Full implementation of the Prague hard fork [#67].
    - **EIP-7702**: Implemented "Set Code Account" (EOA code delegation).
    - **EIP-7623**: Increased calldata cost to reduce block size.
    - **EIP-2537**: Added precompiles for BLS12-381 curve operations.
    - **EIP-4399**: Supplant DIFFICULTY opcode with PREVRANDAO.
    - **EIP-7069**: Revamped CALL instructions.
- Added comprehensive tests for all new EIPs.

## [1.0.0] - 2025-03-21

> **First Major Release** by @mrLSD

This release marks the final transformation of the project from a SputnikVM fork into the standalone **Aurora EVM**
product.

### Added

- **Cancun Hard Fork**: Full support for Cancun hard fork functionality [#85].
- **New Architecture**: Consolidated the project into a single `aurora-evm` crate, eliminating the fragmentation of the
  original SputnikVM.
- **Test Coverage**: Achieved **100% test coverage** using `ethereum/tests` and `ethereum/execution-spec-tests` suites.

### Performance

- Implemented significant performance optimizations.
- **Result**: NEAR gas consumption reduced by **at least 2x** compared to the original SputnikVM (based on Aurora Engine
  benchmarks).

### Changed

- Complete codebase refactoring to improve readability and maintainability.
- Redesigned module structure.

[2.2.1]: https://github.com/aurora-is-near/aurora-evm/compare/v2.2.0...v2.2.1

[2.2.0]: https://github.com/aurora-is-near/aurora-evm/compare/v2.1.3...v2.2.0

[2.1.3]: https://github.com/aurora-is-near/aurora-evm/compare/v2.1.2...v2.1.3

[2.1.2]: https://github.com/aurora-is-near/aurora-evm/compare/v2.1.1...v2.1.2

[2.1.1]: https://github.com/aurora-is-near/aurora-evm/compare/v2.1.0...v2.1.1

[2.1.0]: https://github.com/aurora-is-near/aurora-evm/compare/v2.0.0...v2.1.0

[2.0.0]: https://github.com/aurora-is-near/aurora-evm/compare/v1.0.0...v2.0.0

[1.0.0]: https://github.com/aurora-is-near/aurora-evm/releases/tag/v1.0.0

[#100]: https://github.com/aurora-is-near/aurora-evm/pull/100

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
