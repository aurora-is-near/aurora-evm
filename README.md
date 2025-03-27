[![License](https://img.shields.io/badge/License-MIT-blue.svg)](sLICENSE)
[![Build & Lint Status](https://github.com/aurora-is-near/aurora-evm/actions/workflows/lint.yml/badge.svg)](https://github.com/aurora-is-near/aurora-evm/actions/workflows/lint.yml)
[![Ethereum tests Status](https://github.com/aurora-is-near/aurora-evm/actions/workflows/rust.yml/badge.svg)](https://github.com/aurora-is-near/aurora-evm/actions/workflows/rust.yml)
[![Crates.io version](https://img.shields.io/crates/v/aurora-evm.svg?style=flat-square)](https://crates.io/crates/aurora-evm)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/aurora-evm?style=flat-square&label=crates.io%20downloads)](https://crates.io/crates/aurora-evm)


<div align="center">
  <h1>Aurora EVM</h1>
  <p><strong>A blazing fast 🚀, pure Rust implementation of the Ethereum Virtual Machine (EVM)</strong></p>
</div>

-----

## Features

* **Standalone** - can be launched as an independent process or integrated into other apps
* **Universal** - production ready for any EVM-compatible chain
* **Stateless** - only an execution environment connected to independent State storage
* **Fast** - main focus is on performance

## Status

Production ready. Supported by [Aurora Labs](https://github.com/aurora-is-near/)
and used in production.

Supported Ethereum hard forks:

- [x] Frontier
- [x] Homestead
- [x] Tangerine Whistle
- [x] Spurious Dragon
- [x] Byzantium
- [x] Constantinople
- [x] Istanbul
- [x] Berlin
- [x] London
- [x] Paris (The Merge)
- [x] Shanghai
- [x] Cancun
- [x] Prague

## Ethereum tests supported

- 100% supports of [Ethereum tests](https://github.com/ethereum/tests)
- 100% supports of [Ethereum Execution Spec Tests](https://github.com/ethereum/execution-spec-tests)

## Getting started

To get started, add the following dependency to your `Cargo.toml`:

```toml 
[dependencies]
aurora-evm = "2.0"
```

## License: [MIT](LICENSE)
