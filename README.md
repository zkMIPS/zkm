<p align="center">
    <img alt="zkmreadme" width="1412" src="https://i.ibb.co/xDTXTgH/zkmreadme.gif">
</p>
<p align="center">
    <a href="https://discord.gg/zkm"><img src="https://img.shields.io/discord/700454073459015690?logo=discord"/></a>
    <a href="https://twitter.com/ProjectZKM"><img src="https://img.shields.io/twitter/follow/ProjectZKM?style=social"/></a>
    <a href="https://github.com/zkMIPS/zkm/graphs/contributors"><img src="https://img.shields.io/badge/contributors-17-ee8449"/></a>
</p>

# Table of Contents
- [Table of Contents](#table-of-contents)
- [1. Overview](#1-overview)
- [2. Build Guide](#2-build-guide)
  - [2.1  Local Proving](#21--local-proving)
    - [Requirements:](#requirements)
    - [2.1.1 Local Proving Guide](#211-local-proving-guide)
  - [2.2 Network Proving](#22-network-proving)
    - [Requirements](#requirements-1)
    - [2.2.1 Network Proving Guide](#221-network-proving-guide)
- [3. ZKM Project Template](#3-zkm-project-template)
- [4. FAQs](#4-faqs)
    - [1. My node is unable to compile.](#1-my-node-is-unable-to-compile)
- [5. Contributors](#5-contributors)
  - [General guidance for your PR](#general-guidance-for-your-pr)
- [6. Licenses](#6-licenses)
- [7. Security](#7-security)
# 1. Overview
ZKM is a general verifiable computing infrastructure based on [Plonky2](https://github.com/0xPolygonZero/plonky2) and the [MIPS microarchitecture](https://en.wikipedia.org/wiki/MIPS_architecture), empowering Ethereum as the Global Settlement Layer. The proof generation and verification guide can be found in the [docs](https://docs.zkm.io/guides/proof-generation-guide).
# 2. Build Guide
**ZKM can generate proofs for Go and Rust (guest) Programs.**

There are two ways to prove the program:
- Use your local machine
- Use ZKM Proving network
## 2.1  Local Proving
### Requirements:
- [Go : 1.22.1](https://go.dev/dl)
- [Rust: 1.81.0-nightly](https://www.rust-lang.org/tools/install)
- Hardware: X86 CPU, 32 cores, 32G memory
- OS: Ubuntu22

### 2.1.1 Local Proving Guide
An end-to-end example has been presented in [examples](https://github.com/zkMIPS/zkm/tree/main/prover/examples#examples).
## 2.2 Network Proving
> [!NOTE]
> The proving network is a demo at present. The production version is coming soon.
### Requirements
* CA certificate:  ca.pem, ca.key
* Register at the https://www.zkm.io/apply (Let your public key be in the whitelist)
* Set up a local node for some blockchain(eg, sepolia)
### 2.2.1 Network Proving Guide
An end-to-end example has been presented in [examples](https://github.com/zkMIPS/zkm/blob/main/prover/examples).
# 3. ZKM Project Template
A project template to facilitate creating an end-to-end ZKM project that can generate the EVM-Compatible proof and the on chain verification contract.
[ZKM Project Template](https://github.com/zkMIPS/zkm-project-template/tree/main)
# 4. FAQs
### 1. My node is unable to compile.
- Ensure your machine has `Rust v1.66+` installed. Instructions to [install Rust can be found here.](https://www.rust-lang.org/tools/install)
- If large errors appear during compilation, try running `cargo clean`.
- Ensure `zkMIPS` is started using `./run-client.sh` or `./run-prover.sh`.
# 5. Contributors
This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Any kind of external contributions are encouraged and welcomed!

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## General guidance for your PR
- The PR fixes a bug In the PR description, please clearly but briefly describe the bug, including how to reproduce it, and the error/exception you got, and how your PR fixes the bugs.
- The PR implements a new feature

In the PR description, please clearly but briefly describe
1. what the feature does
2. the approach taken to implement it
3. All PRs for new features must include a suitable test suite.
4. The PR improves performance

To help filter out false positives, the PR description for a performance improvement must clearly identify
 1. the target bottleneck (only one per PR to avoid confusing things!)
 2. how performance is measured
 3. characteristics of the machine used (CPU, OS, #threads if appropriate) performance before and after the PR
# 6. Licenses
The ZKM is distributed under the terms of MIT license.
# 7. Security
This code has not yet been audited, and should not be used in any production systems.
