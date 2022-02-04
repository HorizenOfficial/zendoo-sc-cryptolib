#!/bin/bash

set -eo pipefail

echo "execute the build script $(date)"

cd /build && ./ci/travis_keep_alive.sh && ./ci/build_jar.sh

echo "done $(date)"
