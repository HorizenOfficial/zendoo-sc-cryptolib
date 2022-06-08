#!/bin/bash

set -euo pipefail
export CARGO_AUDIT_EXIT_ON_ERROR="${CARGO_AUDIT_EXIT_ON_ERROR:-true}"

# Running tests
echo "" && echo "=== Running cargo tests ===" && echo ""
cargo test --all-features  

cargo clean

# Running a build
echo "" && echo "=== Running cargo build ===" && echo ""
cargo build -j$(($(nproc)+1)) --release --target=x86_64-pc-windows-gnu
cargo build -j$(($(nproc)+1)) --release --target=x86_64-unknown-linux-gnu

# Running Cargo audit
echo "" && echo "=== Running cargo audit ===" && echo ""
cargo audit --json > /tmp/audit.json
jq '.' /tmp/audit.json

VULNERABILITIES="$(jq '.vulnerabilities.found' /tmp/audit.json)"

if [ "$CARGO_AUDIT_EXIT_ON_ERROR" = "false" ]; then
  echo -e "\nCargo audit disabled"
elif [ "$VULNERABILITIES" = "true" ]; then
  echo -e "\nVulnerabilities have been found"
  jq '.vulnerabilities' /tmp/audit.json
  exit 1
else
  echo -e "\nNo vulnerabilities have been found"
fi

########################

mkdir -p jni/src/main/resources/native/linux64
cp target/x86_64-unknown-linux-gnu/release/libzendoo_sc.so jni/src/main/resources/native/linux64/libzendoo_sc.so

mkdir -p jni/src/main/resources/native/windows64
cp target/x86_64-pc-windows-gnu/release/zendoo_sc.dll jni/src/main/resources/native/windows64/zendoo_sc.dll

cd jni
echo "" && echo "=== Building jar ===" && echo ""
mvn clean package -P !build-extras -DskipTests=true -Dmaven.javadoc.skip=true -B

echo "" && echo "=== Running build tests ===" && echo ""
mvn test -P !build-extras -B

if [ "$CONTAINER_PUBLISH" = "true" ]; then
  echo "======================================================================"
  echo "|              Deploying sdk bundle to maven repository              |"
  echo "======================================================================"
  echo
  mvn deploy -P sign,build-extras --settings ../ci/mvn_settings.xml -B
  echo "======================================================================"
  echo "|         Deploying sdk bundle to maven repository completed         |"
  echo "======================================================================"
  echo
fi
