# Build guide

The library compiles on the `stable` Rust toolchain.
To install Rust, just install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager.

After that, use `cargo`, the standard Rust build tool, to build the library:

```bash
git clone https://github.com/HorizenOfficial/zendoo-sc-cryptolib.git
cd zendoo-sc-cryptolib
cargo build --release
```

This library comes with unit tests for each of the provided crates. Run the tests with:

```bash
cargo test --all-features 
```

Compiling with `adcxq`, `adoxq` and `mulxq` instructions can lead to a 30-70% speedup. These are available on most `x86_64` platforms (Broadwell onwards for Intel and Ryzen onwards for AMD). Run the following command:

```bash
RUSTFLAGS="-C target-feature=+bmi2,+adx" cargo test/build/bench --features asm
```

Tip: If optimising for performance, your mileage may vary with passing `--emit=asm` to `RUSTFLAGS`.

## Java Jar build guide

To be able to build a Java Jar package you can use the `build_jar.sh` script in `ci` folder.
Requirements:
1. Build on Linux (Ubuntu 18.04+, for example) with a cross compilation of a native Rust code for windows target as well.
2. Add windows target support for `cargo`:
    ```
    rustup target add x86_64-pc-windows-gnu
    rustup toolchain install stable-x86_64-pc-windows-gnu
    ```
3. Install maven, openjdk, clang, llvm, mingw:
    ```
    sudo apt-get install clang llvm maven gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64
    ```
4. Configure `mingw` to be able to cross compile the windows target of cryptolib dependencies:
    ```
    update-alternatives --install /usr/bin/x86_64-w64-mingw32-gcc x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix 100
    update-alternatives --install /usr/bin/x86_64-w64-mingw32-g++ x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix 100
    ``` 
5. Run `./ci/build_jar.sh`
