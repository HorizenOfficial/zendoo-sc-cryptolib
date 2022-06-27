#!/bin/bash
# shellcheck disable=SC2046

set -euo pipefail

command -v docker &> /dev/null && have_docker="true" || have_docker="false"
# absolute path to project from relative location of this script
workdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
# defaults if not provided via env
DOCKER_ORG="${DOCKER_ORG:-zencash}"
IMAGE_NAME="${IMAGE_NAME:-sc-ci-base}"
IMAGE_TAG="${IMAGE_TAG:-bionic_rust-1.51.0_jdk-11_latest}"
image="${DOCKER_ORG}/${IMAGE_NAME}:${IMAGE_TAG}"
export CARGO_AUDIT_EXIT_ON_ERROR="${CARGO_AUDIT_EXIT_ON_ERROR:-true}"
export CONTAINER_PUBLISH="${CONTAINER_PUBLISH:-false}"

# run tests in docker or natively
if [ -n "${TESTS:-}" ]; then
  if [ "$have_docker" = "true" ]; then
    if [ -n "${DOCKER_READONLY_USERNAME:-}" ] && [ -n "${DOCKER_READONLY_PASSWORD:-}" ]; then
      echo "$DOCKER_READONLY_PASSWORD" | docker login -u "$DOCKER_READONLY_USERNAME" --password-stdin
    fi
    docker run --rm -t -v "$workdir":/build \
      --entrypoint /build/ci/docker/entrypoint.sh \
      -v "${HOME}"/key.asc:/key.asc \
      -e TESTS \
      -e CARGO_AUDIT_EXIT_ON_ERROR \
      -e CONTAINER_PUBLISH \
      -e LOCAL_USER_ID="$(id -u)" \
      -e LOCAL_GRP_ID="$(id -g)"\
       $(env | grep -E '^CONTAINER_' | sed -n '/^[^\t]/s/=.*//p' | sed '/^$/d' | sed 's/^/-e /g' | tr '\n' ' ') \
      --env-file <(env | grep -E '^(RUSTFLAGS=|CARGOARGS=|RUST_CROSS_TARGETS=|RUSTUP_TOOLCHAIN=).+$') \
      "${image}" /build/ci/run_tests.sh
  else
    "${workdir:-.}/ci/run_tests.sh"
  fi
fi