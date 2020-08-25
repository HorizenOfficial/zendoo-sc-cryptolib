
# zendoo-sc-cryptolib

`zendoo-sc-cryptolib` is a Rust crate that exposes to Java, through JNI, the [ginger-lib](https://github.com/ZencashOfficial/ginger-lib) components needed by the [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") sidechain SDK.

In particular it exposes interfaces to:

* handle the finite fields that are the alphabets of the zk Proving Systems
* call the Poseidon function, a Snark friendly hashing algorithm
* use a Poseidon-based Merkle Tree coming in different variants (in-memory random access, persistent sparse, persistent lazy sparse) 
* compute and verify Schnorr signatures, handle associated keypairs
* compute and verify a VRF proof, fetch a VRF output, handle associated keypairs (to support Ouroborous-style PoS sidechain consensus)
* create and manage Zendoo Sidechain proofs

The library includes also an example of a simple Zendoo [sidechain proving circuit](demo-circuit) that can be used to create proofs for backward transfer certificates. This demo circuit can prove that a given certificate was signed by a minimum number of signers, all belonging to a defined set of approved signers. For more info, pls see the specific [document](doc).
The circuit is offered as an example to developers, to help them build their own circuits, that will match their sidechain logic and needs.

**Please note: the code is in development. No guarantees are provided about its security and functionality**


## Build guide

The library can be built by using Cargo:
 
```
	cargo build
```  
Note: You need `clang` installed. 
There are a few Rust tests that can be executed still with the usual Cargo command:  

```
	cargo test
```  


## Contributing

Contributions are welcomed! Bug fixes and new features can be initiated through GitHub pull requests. To speed the code review process, please adhere to the following guidelines:

* Follow Horizen repositories' *code of conduct*
* Follow Horizen repositories' *styling guide* 
* Please gpg sign your commits 
* Please make sure you push your pull requests to the development branch

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

## License

The code is licensed under the following license:

 * MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in ginger-lib by you shall be licensed as above, without any additional terms or conditions.

[![License MIT](https://img.shields.io/badge/license-MIT-blue.svg)](http://opensource.org/licenses/MIT)

  
