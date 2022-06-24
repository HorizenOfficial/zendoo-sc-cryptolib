#!/bin/bash
# shellcheck disable=SC2086

set -eo pipefail
retval=0

# Running cargo tests
echo "" && echo "=== Running cargo tests ===" && echo ""
cargo $CARGOARGS test --all-features || retval="$?"

# Running cargo clean
echo "" && echo "=== Running cargo clean ===" && echo ""
if grep -q 'Cargo.lock' .gitignore &> /dev/null; then
  rm -f Cargo.lock
fi
cargo $CARGOARGS clean

exit "$retval"
