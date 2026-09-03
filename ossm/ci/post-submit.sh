#!/bin/bash

set -exo pipefail

DIR=$(cd "$(dirname "$0")" ; pwd -P)

# shellcheck disable=SC1091
source "${DIR}/common.sh"

GCS_PROJECT=${GCS_PROJECT:-maistra-prow-testing}
ARTIFACTS_GCS_PATH=${ARTIFACTS_GCS_PATH:-gs://maistra-prow-testing/proxy}

# Build Envoy
bazel_build envoy_tar

# Copy artifacts to GCS
SHA="$(git rev-parse --verify HEAD)"

ARTIFACT="envoy-alpha-${SHA}.tar.gz"
cp -L bazel-bin/envoy_tar.tar.gz "${ARTIFACT}"

# Upload to GCS (skipped when SKIP_GCS_UPLOAD=true, e.g. in Testing Farm context)
if [[ "${SKIP_GCS_UPLOAD:-false}" != "true" ]]; then
  gcloud auth activate-service-account \
    --key-file="${GOOGLE_APPLICATION_CREDENTIALS:?GOOGLE_APPLICATION_CREDENTIALS must be set for GCS upload}"
  gcloud config set project "${GCS_PROJECT}"
  gsutil cp "${ARTIFACT}" "${ARTIFACTS_GCS_PATH}/${ARTIFACT}"
  gsutil cp "${ARTIFACTS_GCS_PATH}/${ARTIFACT}" "${ARTIFACTS_GCS_PATH}/envoy-centos-alpha-${SHA}.tar.gz"
fi
