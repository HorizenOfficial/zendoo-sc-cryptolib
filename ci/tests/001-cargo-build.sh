#!/bin/bash
# shellcheck disable=SC2086

set -eo pipefail

retval=0

echo "" && echo "=== Running cargo build ===" && echo ""
cargo $CARGOARGS build -j$(($(nproc)+1)) --release --target=x86_64-pc-windows-gnu || retval="$?"
cargo $CARGOARGS build -j$(($(nproc)+1)) --release --target=x86_64-unknown-linux-gnu || retval="$?"
exit "$retval"
