<h1 align="center">zendoo-sc-cryptolib</h1>
<p align="center">
    <a href= "https://github.com/HorizenOfficial/zendoo-sc-cryptolib/releases"><img src="https://img.shields.io/github/release/HorizenOfficial/zendoo-sc-cryptolib.svg"></a>
    <a href="AUTHORS"><img src="https://img.shields.io/github/contributors/HorizenOfficial/zendoo-sc-cryptolib.svg?"></a>
    <a href="https://travis-ci.com/github/HorizenOfficial/zendoo-sc-cryptolib"><img src="https://app.travis-ci.com/HorizenOfficial/zendoo-sc-cryptolib.svg?branch=master"></a>
    <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square"></a>
</p>

`zendoo-sc-cryptolib` is a Rust crate that exposes to Java, through JNI, the [ginger-lib](https://github.com/HorizenOfficial/ginger-lib) components needed by the [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") sidechain SDK.

In particular it exposes interfaces to:

* handle the finite fields that are the alphabets of the zk Proving Systems
* call the *Poseidon* function, a Snark friendly hashing algorithm
* use a full in-memory *Poseidon-based Merkle Tree*, thus optimized for performance but limited in size (depending on the available RAM)
* manage the *SCTxsCommitmentTree*, as described in section 4.1.3 of the [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") paper
* compute and verify *Schnorr* signatures, handle associated keypairs
* compute and verify a VRF proof, fetch a VRF output, handle associated keypairs (to support *Ouroborous*-style PoS sidechain consensus)
* create and manage *Zendoo* Sidechain proofs

The library includes also an example of a simple Zendoo [sidechain proving circuit](demo-circuit) that can be used to create proofs for backward transfer certificates. This demo circuit can prove that a given certificate was signed by a minimum number of signers, all belonging to a defined set of approved signers. For more info, pls see the specific [document](doc).
The circuit is offered as an example to developers, to help them build their own circuits, that will match their sidechain logic and needs.

**Please note: the code is in development. No guarantees are provided about its security and functionality**

## Release Notes

The current release does not yet serve proof composition.
The proving system has been switched from [Groth16](https://eprint.iacr.org/2016/260.pdf) to our Marlin variant [*Coboundary Marlin*](https://github.com/HorizenLabs/marlin).
Support has been introduced to create *Final Darlin* proofs, as per last step of our recursive PCD scheme (See [HGB](https://eprint.iacr.org/2021/930) for details), but not yet implemented.

## Build guide

The library compiles on the `1.51.0 stable` toolchain of the Rust compiler.
To install Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager.
Once `rustup` is installed, install the appropriate Rust toolchain by invoking:
```bash
rustup install 1.51.0
```

After that, use `cargo`, the standard Rust build tool, to build the library:
```bash
git clone https://github.com/HorizenOfficial/zendoo-sc-cryptolib.git
cd zendoo-sc-cryptolib
cargo build --release
```
This library comes with unit tests for each of the provided crates. Run the tests with:
```bash
cargo test
``` 
More detailed build guide, as well as instructions to build the .jar, can be found in in our [build guide](BUILD.md).
