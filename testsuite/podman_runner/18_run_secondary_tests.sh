#!/bin/bash

set -xe
TESTS="$@"
sudo -i podman exec controller bash -c "export SCC_CREDENTIALS=\"test|test\" && export GITPROFILES=https://github.com/uyuni-project/uyuni.git#:testsuite/features/profiles/github_runner && export PXEBOOT_IMAGE=sles15sp4 && export BUILD_HOST=buildhost && export AUTH_REGISTRY=${AUTH_REGISTRY} && export AUTH_REGISTRY_CREDENTIALS=\"${AUTH_REGISTRY_CREDENTIALS}\" && export NO_AUTH_REGISTRY=${NO_AUTH_REGISTRY} && export PUBLISH_CUCUMBER_REPORT=${PUBLISH_CUCUMBER_REPORT} && export PROVIDER=podman && export SERVER=server && export HOSTNAME=controller && export SSH_MINION=opensusessh && export MINION=sle_minion && export RHLIKE_MINION=rhlike_minion && export TAGS=\"\\\"not @flaky\\\"\" && export DEBLIKE_MINION=deblike_minion && cd /testsuite && rake cucumber:secondary ${TESTS}"
