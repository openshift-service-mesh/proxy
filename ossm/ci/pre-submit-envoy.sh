#!/bin/bash

set -e
set -o pipefail
set -x

DIR=$(cd "$(dirname "$0")" ; pwd -P)

# shellcheck disable=SC1091
source "${DIR}/common.sh"

# Run envoy's utests
time bazel_test @envoy//test/...
