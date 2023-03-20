#!/bin/bash
set -eo pipefail
retval=0

# Checking JAVADOC lint parameter(s)
javadoc_params=''
if [ "${DISABLE_JAVADOC_LINT}" = "true" ]; then
  echo -e "\nJavadoc lint is disabled"
  javadoc_params='-Ddoclint=none'
elif [ "${DISABLE_JAVADOC_LINT}" != "false" ]; then
  echo -e "\nERROR: DISABLE_JAVADOC_LINT should be only true|false and not '$DISABLE_JAVADOC_LINT'"
  exit 1
fi

# Publishing maven package(s)
cd jni
if [[ "${TRAVIS_TAG}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?(-SNAPSHOT){1}[0-9]*$ ]]; then
  echo "" && echo "=== Publishing development release on Sonatype Nexus repository. Timestamp is: $(date '+%a %b %d %H:%M:%S %Z %Y') ===" && echo ""
  mvn deploy -P sign,build-extras --settings ../ci/mvn_settings.xml ${javadoc_params} -DskipTests=true -B || retval="$?"
elif [[ "${TRAVIS_TAG}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]]; then
  echo "" && echo "=== Publishing production release on Maven repository. Timestamp is: $(date '+%Y-%m-%d %H:%M') ===" && echo ""
  mvn deploy -P sign,build-extras --settings ../ci/mvn_settings.xml ${javadoc_params} -DskipTests=true -B || retval="$?"
else
  echo "" && echo "=== Not going to publish!!! Release tag = ${TRAVIS_TAG} did not match either DEV or PROD format requirements ===" && echo ""
fi

exit "$retval"