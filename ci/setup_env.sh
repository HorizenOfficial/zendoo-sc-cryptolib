#!/bin/bash

set -eo pipefail

export CONTAINER_PUBLISH="false"
PUBLISH_BUILD="${PUBLISH_BUILD:-false}"
pom_version="$(xpath -q -e '/project/version/text()' jni/pom.xml)"

echo "TRAVIS_TAG: $TRAVIS_TAG"
echo "jni/pom.xml version: $pom_version"

# Functions
function import_gpg_keys() {
  # shellcheck disable=SC2145
  printf "%s\n" "Tagged build, fetching keys:" "${@}" ""
  # shellcheck disable=SC2207
  declare -r my_arr=( $(echo "${@}" | tr " " "\n") )

  for key in "${my_arr[@]}"; do
    echo "Importing key: ${key}"
    gpg -v --batch --keyserver hkps://keys.openpgp.org --recv-keys "${key}" ||
    gpg -v --batch --keyserver hkp://keyserver.ubuntu.com --recv-keys "${key}" ||
    gpg -v --batch --keyserver hkp://pgp.mit.edu:80 --recv-keys "${key}" ||
    gpg -v --batch --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "${key}"
  done
}

function check_signed_tag() {
  # Checking if git tag signed by the maintainers
  if git verify-tag -v "${1}"; then
    echo "${1} is a valid signed tag"
  else
    echo "Git tag's = ${1} gpg signature is NOT valid. The build is not going to be released..."
  fi
}

# empty key.asc file in case we're not signing
touch "${HOME}/key.asc"

if [ -n "${TRAVIS_TAG}" ] && [ "${PUBLISH_BUILD}" = true ]; then
  # checking if MAINTAINER_KEYS is set
  if [ -z "${MAINTAINER_KEYS}" ]; then
    echo "MAINTAINER_KEYS variable is not set. Make sure to set it up for release build!!!"
    exit 1
  fi

  # shellcheck disable=SC2155
  export GNUPGHOME="$(mktemp -d 2>/dev/null || mktemp -d -t 'GNUPGHOME')"

  # Checking PROD vs DEV build
  echo "The current production branch is: ${PROD_RELEASE_BRANCH}"

  import_gpg_keys "${MAINTAINER_KEYS}"

  if (check_signed_tag "${TRAVIS_TAG}"); then
    if [[ "${IMAGE_TAG}" != *"nightly"* ]]; then
      # Prod vs dev release
      if ( git branch -r --contains "${TRAVIS_TAG}" | grep -xqE ". origin\/${PROD_RELEASE_BRANCH}$" ); then
        # Checking if package version matches PROD release version
        if ! [[ "${pom_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
          echo "Aborting, pom version is in the wrong format."
          exit 1
        fi

        # Checking Github tag format
        if ! [[ "${TRAVIS_TAG}" == "${pom_version}" ]]; then
          echo -e "\nTag format differs from the pom file version."
          echo -e "Github tag name: ${TRAVIS_TAG}\nPom file version: ${pom_version}.\nPublish stage is NOT going to run!!!"
          exit 1
        fi

        # Announcing PROD release
        echo "" && echo "=== Production release build ===" && echo ""
        echo "Fetching maven gpg signing keys."
        curl -sLH "Authorization: token ${GITHUB_TOKEN}" -H "Accept: application/vnd.github.v3.raw" "${MAVEN_KEY_ARCHIVE_URL}" |
          openssl enc -d -aes-256-cbc -md sha256 -pass pass:"${MAVEN_KEY_ARCHIVE_PASSWORD}" |
          tar -xzf- -C "${HOME}"
        export CONTAINER_PUBLISH="true"
      else
        # Checking if package version matches DEV release version
        if ! [[ "${pom_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-SNAPSHOT){1}$ ]]; then
          echo "Aborting, package version is in the wrong format."
          exit 1
        fi

        # Checking Github tag format
        if ! [[ "${TRAVIS_TAG}" =~ "${pom_version}"[0-9]*$ ]]; then
          echo "Aborting, tag format differs from the version under build.sbt file."
          exit 1
        fi

        # Announcing DEV release
        echo "" && echo "=== Development release build ===" && echo ""
        echo "Fetching maven gpg signing keys."
        curl -sLH "Authorization: token ${GITHUB_TOKEN}" -H "Accept: application/vnd.github.v3.raw" "${MAVEN_KEY_ARCHIVE_URL}" |
          openssl enc -d -aes-256-cbc -md sha256 -pass pass:"${MAVEN_KEY_ARCHIVE_PASSWORD}" |
          tar -xzf- -C "${HOME}"
        export CONTAINER_PUBLISH="true"
      fi
    fi
  fi
fi

# unset credentials if not publishing
if [ "${CONTAINER_PUBLISH}" = "false" ]; then
  export CONTAINER_OSSRH_JIRA_USERNAME=""
  export CONTAINER_OSSRH_JIRA_PASSWORD=""
  export CONTAINER_GPG_KEY_NAME=""
  export CONTAINER_GPG_PASSPHRASE=""
  unset CONTAINER_OSSRH_JIRA_USERNAME
  unset CONTAINER_OSSRH_JIRA_PASSWORD
  unset CONTAINER_GPG_KEY_NAME
  unset CONTAINER_GPG_PASSPHRASE
  echo "" && echo "=== NOT a release build ===" && echo ""
fi

# unset credentials after use
export GITHUB_TOKEN=""
export MAVEN_KEY_ARCHIVE_URL=""
export MAVEN_KEY_ARCHIVE_PASSWORD=""
unset GITHUB_TOKEN
unset MAVEN_KEY_ARCHIVE_URL
unset MAVEN_KEY_ARCHIVE_PASSWORD

set +eo pipefail