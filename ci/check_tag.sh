#!/bin/bash

set -eo pipefail

pom_version="$(xpath -q -e '/project/version/text()' jni/pom.xml)"

echo "TRAVIS_TAG: $TRAVIS_TAG"
echo "jni/pom.xml version: $pom_version"

export PUBLISH="false"

if [ ! -z "${TRAVIS_TAG}" ]; then
  export GNUPGHOME="$(mktemp -d 2>/dev/null || mktemp -d -t 'GNUPGHOME')"
  echo "Tagged build, fetching maintainer keys."
    gpg -v --batch --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys $MAINTAINER_KEYS ||
    gpg -v --batch --keyserver hkp://ipv4.pool.sks-keyservers.net --recv-keys $MAINTAINER_KEYS ||
    gpg -v --batch --keyserver hkp://pgp.mit.edu:80 --recv-keys $MAINTAINER_KEYS
  if git verify-tag -v "${TRAVIS_TAG}"; then
    echo "Valid signed tag"
    if [ "${TRAVIS_TAG}" != "${pom_version}" ]; then
       echo "tag different from the pom file"
       exit 1
    else
      export PUBLISH="true"
    fi
  fi
fi

if [ "$PUBLISH" = "false" ]; then
  export PACKAGECLOUD_TOKEN=""
  unset PACKAGECLOUD_TOKEN
fi

set +eo pipefail
