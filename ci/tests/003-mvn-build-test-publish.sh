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

# Publishing if a release build
if [ "$CONTAINER_PUBLISH" = "true" ]; then
  echo "======================================================================"
  echo "|              Deploying sdk bundle to maven repository              |"
  echo "======================================================================"
  echo
  mvn deploy -P sign,build-extras --settings ../ci/mvn_settings.xml -DskipTests=true -B || retval="$?"
else
  echo "" && echo "=== This is NOT a release build. CONTAINER_PUBLISH variable is set to ${CONTAINER_PUBLISH}. ===" && echo ""
fi

exit "$retval"

