#!/bin/bash
# shellcheck disable=SC2154

set -Eeo pipefail

# Get the directory of the currently executing script and its parent dir
current_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )";
base_dir="$( dirname "${current_dir%/*}" )"

DOCKER_ORG="${DOCKER_ORG:-zencash}"
IMAGE_NAME="${IMAGE_NAME:-sc-ci-base}"
IMAGE_TAG="${IMAGE_TAG:-bionic_rust-1.51.0_jdk-11_latest}"
image="${DOCKER_ORG}/${IMAGE_NAME}:${IMAGE_TAG}"

have_docker="false"
command -v docker &> /dev/null && have_docker="true"

# Functions
define(){ IFS=$'\n' read -r -d '' "${1}" || true; }

# Script content
define execute << SCRIPT
#!/bin/bash

set -euo pipefail

# Get the directory of the currently executing script and its parent dir
current_dir=\$( cd \$( dirname ${BASH_SOURCE[0]} ) && pwd )
base_dir=\$( dirname \${current_dir%/*} )

# pom xml file locations
jni_xml_location=\${base_dir}/jni

# cargo.toml file locations
api_cargo_location=\${base_dir}/api
demo_circuit_cargo_location=\${base_dir}/demo-circuit
ouroboros_cargo_location=\${base_dir}/ouroboros

# cargo.lock file location
cargo_lock_location=\${base_dir}

# Functions
function fn_die() {
  echo -e \${1} >&2
  exit \${2:-1}
}

function usage() {
  cat << BLOCK
  Usage: Provide OLD and NEW versions as the 1st and 2nd arguments respectively.
         It has to match the following format:
         DIGIT.DIGIT.DIGIT or DIGIT.DIGIT.DIGIT-SNAPSHOT

         For example:
         ./set_version.sh 5.5.5 5.5.5-SNAPSHOT
         ./set_version.sh 5.5.5-SNAPSHOT 5.5.5
BLOCK
  fn_die "Exiting ..."
}

# Checking for exact amount of arguments as the first step
if [[ $# -eq 2 ]]; then
    version_old="${1}"
    version_new="${2}"
else
    usage
fi

# Checking the format of the versions
if ! [[ \${version_old} =~ ^[0-9]+\.[0-9]+\.[0-9]+(-SNAPSHOT)?$ ]]; then
  usage
fi

if ! [[ \${version_new} =~ ^[0-9]+\.[0-9]+\.[0-9]+(-SNAPSHOT)?$ ]]; then
  usage
fi

# Checking if maven is installed
if ! command -v mvn >/dev/null; then
  echo "" && echo "=== Maven needs to be installed!!! ===" && echo ""
  fn_die "Refer to the official Apache Maven Project: https://maven.apache.org/install.html\nExiting ..."
fi

# Checking if cargo is installed for MAC and Linux OS
if ! command -v cargo >/dev/null; then
  if ! command -v "${HOME}"/.cargo/bin/cargo >/dev/null; then
    echo "" && echo "=== Cargo needs to be installed!!! ===" && echo ""
    fn_die "Use the following command to install it: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\nExiting ..."
  fi
fi

# Checking if cargo-get crate is installed
if ! command -v \${HOME}/.cargo/bin/cargo-get >/dev/null; then
  echo "Cargo cargo-get crate needs to be installed."
  echo "" && echo "=== Installing cargo-get ===" && echo ""
  cargo install cargo-get --version 0.3.3
fi

# Checking if set-cargo-version crate is installed
if ! command -v \${HOME}/.cargo/bin/set-cargo-version >/dev/null; then
  echo "Cargo set-cargo-version crate needs to be installed."
  echo "" && echo "=== Installing set-cargo-version ===" && echo ""
  cargo install set-cargo-version --version 1.0.0
fi

## Changing version numbers under pom.xml file(s)
cd \${jni_xml_location}
current_pom_version=\$(mvn help:evaluate -q -Dexpression=project.version -DforceStdout 2>/dev/null)
if [ \${version_old} != \${current_pom_version} ]; then
  fn_die "Fix it! The OLD version does not match with CURRENT version under \${jni_xml_location}/pom.xml file\nCurrent version is: \${current_pom_version}.\nExiting ..."
fi

echo "" && echo "=== Modifying pom file under \${jni_xml_location} location ===" && echo ""
mvn versions:set -DnewVersion=\${version_new}

# Changing version number under cargo.toml file(s)
for dir in \${api_cargo_location} \${demo_circuit_cargo_location} \${ouroboros_cargo_location}; do
  # Checking if OLD version matches with the CURRENT version in pom file(s)
  cd \${dir}
  current_cargo_version=\$(\${HOME}/.cargo/bin/cargo-get version)
  if [ \${version_old} != \${current_cargo_version} ]; then
    fn_die "Fix it! The OLD version does not match with CURRENT version under \${dir}/Cargo.toml file\nCurrent version is: \${current_cargo_version}.\nExiting ..."
  fi

  echo "" && echo "=== Modifying Cargo.toml file under \${dir} location ===" && echo ""

  # Setting the new version
  \${HOME}/.cargo/bin/set-cargo-version \${dir}/Cargo.toml \${version_new}
done

# Changing crates version under Cargo.lock file
# shellcheck disable=SC2001
version_old_dot_escaped=\$(sed -e 's/\./\\\./g' <<< \${version_old})

for package in api demo-circuit; do
  echo "Changing \${package} package under Cargo.lock file version from \${version_old} to \${version_new}"

  current_lock_file_version=\$(sed -n "/^name = \"\${package}\"$/{n;p}" \${cargo_lock_location}/Cargo.lock | cut -d ' ' -f3 | tr -d '"')
  if [ \${version_old} != \${current_lock_file_version} ]; then
    fn_die "Fix it! Provided OLD version of \${package} package does not match with CURRENT version under \${cargo_lock_location}/Cargo.lock file\nCurrent version is: \${current_lock_file_version}.\nExiting ..."
  fi

  sed -i "/^name = \"\${package}\"$/{n;s/\${version_old_dot_escaped}/\${version_new}/}" \${cargo_lock_location}/Cargo.lock
done

echo "" && echo "=== DONE ===" && echo ""
echo -e "OLD version: \${version_old}\nNEW version: \${version_new}"

exit 0
SCRIPT

## If docker is installed running the script inside a container. Otherwise running inside local bash shell
cmd='bash'
if [ "$have_docker" = "true" ]; then
  echo "" && echo "=== Docker is installed. Running the script inside docker container ===" && echo ""
  cmd="docker run --rm -i -v ${base_dir}:/build -w /build ${image} ${cmd}"
fi

${cmd} <<< "${execute}"

