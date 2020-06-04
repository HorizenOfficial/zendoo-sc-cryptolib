#!/bin/bash

set -eo pipefail

cargo clean

cargo build -j$(($(nproc)+1)) --release --target=x86_64-pc-windows-gnu
cargo build -j$(($(nproc)+1)) --release --target=x86_64-unknown-linux-gnu


mkdir -p jni/src/main/resources/native/linux64
cp target/x86_64-unknown-linux-gnu/release/libzendoo_sc.so jni/src/main/resources/native/linux64/libzendoo_sc.so

mkdir -p jni/src/main/resources/native/windows64
cp target/x86_64-pc-windows-gnu/release/zendoo_sc.dll jni/src/main/resources/native/windows64/zendoo_sc.dll

cd jni
mvn clean package

if [ "$PUBLISH" = "true" ]; then
  echo "Deploying package to maven repository."
  mvn deploy
fi
