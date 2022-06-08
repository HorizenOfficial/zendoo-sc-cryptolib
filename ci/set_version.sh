#!/bin/bash

set -euo pipefail

# Get the directory of the currently executing script and its parent dir
current_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )";
parent_dir="${current_dir%/*}"

# pom xml file locations
jni_xml_location="${parent_dir}/jni"

# cargo.toml file locations
api_cargo_location="${parent_dir}/api"
demo_circuit_cargo_location="${parent_dir}/demo-circuit"
ouroboros_cargo_location="${parent_dir}/ouroboros"

# cargo.lock file location
cargo_lock_location="${parent_dir}"

# Functions
function fn_die() {
  echo -e "${1}" >&2
  exit "${2:-1}"
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

# Checking if cargo is installed for MAC and Linux OS
if ! command -v cargo >/dev/null; then
  if ! command -v "${HOME}"/.cargo/bin/cargo >/dev/null; then
    echo "Cargo needs to be installed."
    echo "Use the following command to install it: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fn_die "Exiting ..."
  fi
fi

# Checking if required cargo crates are installed
if ! command -v "${HOME}"/.cargo/bin/cargo-get >/dev/null || ! command -v "${HOME}"/.cargo/bin/set-cargo-version >/dev/null; then
  echo "Cargo cargo-get and set-cargo-version crates need to be installed."
  echo "Use the following command to install cargo-get:         cargo install cargo-get"
  echo "Use the following command to install set-cargo-version: cargo install set-cargo-version"
  fn_die "Exiting ..."
fi

# Checking for exact amount of arguments as the first step
if [[ $# -eq 2 ]]; then
    version_old="${1}"
    version_new="${2}"
else
    usage
fi

# Checking the format of the versions
if ! [[ "${version_old}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-SNAPSHOT)?$ ]]; then
  usage
fi

if ! [[ "${version_new}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-SNAPSHOT)?$ ]]; then
  usage
fi

# Changing version numbers under pom.xml file(s)
for dir in "${jni_xml_location}"; do
  # Checking if OLD version matches with the CURRENT version in pom file(s)
  cd "${dir}"
  current_pom_version="$(mvn help:evaluate -q -Dexpression=project.version -DforceStdout 2>/dev/null)"
  if [ "${version_old}" != "${current_pom_version}" ]; then
    fn_die "Fix it! The OLD version does not match with CURRENT version under ${dir}/pom.xml file\nCurrent version is: ${current_pom_version}"
  fi

  echo "" && echo "=== Modifying pom file under ${dir} location ===" && echo ""

  mvn versions:set -DnewVersion="${version_new}"
done

# Changing version number under cargo.toml file(s)
for dir in "${api_cargo_location}" "${demo_circuit_cargo_location}" "${ouroboros_cargo_location}"; do
  # Checking if OLD version matches with the CURRENT version in pom file(s)
  cd "${dir}"
  current_cargo_version="$("${HOME}"/.cargo/bin/cargo-get version)"
  if [ "${version_old}" != "${current_cargo_version}" ]; then
    fn_die "Fix it! The OLD version does not match with CURRENT version under ${dir}/Cargo.toml file\nCurrent version is: ${current_pom_version}"
  fi

  echo "" && echo "=== Modifying Cargo.toml file under ${dir} location ===" && echo ""

  # Final version after
  "${HOME}"/.cargo/bin/set-cargo-version "${dir}/Cargo.toml" "${version_new}"
done

# Changing crates version under caro.lock file
# shellcheck disable=SC2001
version_old_dot_escaped="$(sed -e 's/\./\\./g' <<< "${version_old}")"

for package in api demo-circuit; do
  echo "Changing ${package} package under Cargo.lock file version from ${version_old} to ${version_new}"

  current_lock_file_version=$(sed -n "/^name = \"${package}\"$/{n;p}" "${cargo_lock_location}"/Cargo.lock | cut -d ' ' -f3 | tr -d '"')
  if [ "${version_old}" != "${current_lock_file_version}" ]; then
    fn_die "Fix it! Provided OLD version of ${package} package does not match with CURRENT version under ${cargo_lock_location}/Cargo.lock file\nCurrent version is: ${current_lock_file_version}"
  fi

  sed -i "/^name = \"${package}\"$/{n;s/${version_old_dot_escaped}/${version_new}/}" "${cargo_lock_location}"/Cargo.lock
done

echo "" && echo "=== DONE ===" && echo ""
echo -e "OLD version: ${version_old}\nNEW version: ${version_new}"

exit 0