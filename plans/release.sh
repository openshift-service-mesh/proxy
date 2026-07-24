set -euo pipefail

CNAME="ossm-release-$$"
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

TMPLOG=$(mktemp)

echo "=== Building release artifact (envoy_tar) ==="
# SKIP_GCS_UPLOAD=true: build-only run inside TF, no GCS upload from the VM.
# The artifact is placed in TMT_TEST_DATA for TF archiving.
# GCS upload is handled by release.yaml on the GHA runner via upload-to-gcs.sh.
podman exec --workdir /work "${CNAME}" \
  bash -c 'SKIP_GCS_UPLOAD=true bash ossm/ci/post-submit.sh' > "${TMPLOG}" 2>&1
EXIT_CODE=$?

if [[ ${EXIT_CODE} -eq 0 ]]; then
  echo "=== Build output — first 300 lines ==="
  head -300 "${TMPLOG}"
  echo "=== Build output — last 300 lines ==="
  tail -300 "${TMPLOG}"

  ARTIFACT=$(ls envoy-alpha-*.tar.gz 2>/dev/null | head -1)
  cp "${ARTIFACT}" "${TMT_TEST_DATA}/${ARTIFACT}"
  echo "Artifact built: ${ARTIFACT} ($(du -sh "${ARTIFACT}" | cut -f1))"

else
  echo "=== Build FAILED — full output ==="
  cat "${TMPLOG}"
fi

rm -f "${TMPLOG}"
exit ${EXIT_CODE}
