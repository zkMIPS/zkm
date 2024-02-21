# ZKM

ZKM is a general verifiable computing infrastructure based on [Plonky2](https://github.com/0xPolygonZero/plonky2) and the [MIPS microarchitecture](https://en.wikipedia.org/wiki/MIPS_architecture), empowering Ethereum as the Global Settlement Layer.

# Building

In order to build the application, zkm requires a latest nightly toolchain. Just run `cargo build --release` in zkm directory.

# Running the examples

An end-to-end example has been presented in [examples](./examples).

# Guidance for external contributors

Any kind of external contributions are encouraged and welcomed!

## General guidance for your PR

* The PR fixes a bug
In the PR description, please clearly but briefly describe the bug, including how to reproduce, and the error/exception you got, and how your PR fixes the bugs.

* The PR implements a new feature

In the PR description, please clearly but briefly describe

> 1. what the feature does
> 2. the approach taken to implement it
> 3. All PRs for new features must include a suitable test suite.

* The PR improves performance

To help filter out false positives, the PR description for a performance improvement must clearly identify

> 1. the target bottleneck (only one per PR to avoid confusing things!)
> 2. how performance is measured
> 3. characteristics of the machine used (CPU, OS, #threads if appropriate) performance before and after the PR

# Licenses

The ZKM is distributed under the terms of MIT license.

# Security

This code has not yet been audited, and should not be used in any production systems.

