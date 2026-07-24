set -euo pipefail

CNAME="ossm-build-$$"
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

TMPLOG=$(mktemp)

# Phase 1: build + test (equivalent to Prow pre-submit)
podman exec --workdir /work "${CNAME}" \
  bash ossm/ci/pre-submit.sh > "${TMPLOG}" 2>&1
EXIT_CODE=$?

if [[ ${EXIT_CODE} -eq 0 ]]; then
  echo "=== Build succeeded — first 300 lines ==="
  head -300 "${TMPLOG}"
  echo "=== Build succeeded — last 300 lines ==="
  tail -300 "${TMPLOG}"

  # Phase 2: package the release artifact using the warm Bazel cache (~15s).
  echo "=== Packaging release artifact (envoy_tar) ==="
  podman exec --workdir /work "${CNAME}" \
    bash -c 'SKIP_GCS_UPLOAD=true bash ossm/ci/post-submit.sh' >> "${TMPLOG}" 2>&1

  ARTIFACT=$(ls envoy-alpha-*.tar.gz 2>/dev/null | head -1)
  cp "${ARTIFACT}" "${TMT_TEST_DATA}/${ARTIFACT}"
  echo "Release artifact: ${ARTIFACT} ($(du -sh "${ARTIFACT}" | cut -f1))"

else
  echo "=== Build FAILED — full output ==="
  cat "${TMPLOG}"
fi

rm -f "${TMPLOG}"
exit ${EXIT_CODE}
