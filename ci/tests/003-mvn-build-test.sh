#!/bin/bash
set -eo pipefail
retval=0

# Building jar package
echo "" && echo "=== Building jar ===" && echo ""
mkdir -p jni/src/main/resources/native/linux64
cp target/x86_64-unknown-linux-gnu/release/libzendoo_sc.so jni/src/main/resources/native/linux64/libzendoo_sc.so

mkdir -p jni/src/main/resources/native/windows64
cp target/x86_64-pc-windows-gnu/release/zendoo_sc.dll jni/src/main/resources/native/windows64/zendoo_sc.dll

cd jni
mvn clean package -DskipTests=true -B || retval="$?"

# Running mvn tests
echo "" && echo "=== Running maven build tests ===" && echo ""
mvn test -B || retval="$?"

exit "$retval"

