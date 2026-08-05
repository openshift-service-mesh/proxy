# Sourced by build.sh / release.sh; not meant to be executed directly.

# Validate SOURCE_REPO is a github.com HTTPS URL (prevents shell injection and SSRF)
if [[ ! "${SOURCE_REPO}" =~ ^https://github\.com/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+\.git$ ]]; then
  echo "ERROR: SOURCE_REPO must be a github.com HTTPS URL, got: ${SOURCE_REPO}" >&2
  exit 1
fi
# Validate SOURCE_REF is a 40-char hex SHA (prevents shell injection)
if [[ ! "${SOURCE_REF}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: SOURCE_REF must be a 40-char hex SHA, got: ${SOURCE_REF}" >&2
  exit 1
fi

sysctl -w user.max_user_namespaces=15000

git clone "${SOURCE_REPO}" proxy-src
cd proxy-src
git checkout "${SOURCE_REF}"

LOCAL_JOBS=$(( $(nproc) * 3 / 4 ))
LOCAL_RAM=$(( $(free -m | awk '/^Mem:/{print $2}') * 85 / 100 ))

CNAME="${CNAME:-ossm-$$}"
_TMPLOG=""
_cleanup() {
  rm -f "${_TMPLOG}"
  podman rm -f "${CNAME}" 2>/dev/null || true
}
trap _cleanup EXIT

podman run -d --name "${CNAME}" \
  --pids-limit=-1 \
  -e CI=true \
  -e LOCAL_JOBS="${LOCAL_JOBS}" \
  -e LOCAL_CPU_RESOURCES="$(nproc)" \
  -e LOCAL_RAM_RESOURCES="${LOCAL_RAM}" \
  -v "$(pwd)":/work:z -w /work \
  "$(cat ossm/ci/builder-image)" \
  sleep infinity

run_in_podman() {
  local cmd="$1"
  _TMPLOG=$(mktemp)

  local exit_code=0
  podman exec --workdir /work "${CNAME}" bash -c "${cmd}" > "${_TMPLOG}" 2>&1 || exit_code=$?

  if [[ ${exit_code} -eq 0 ]]; then
    echo "=== first 300 lines ==="
    head -300 "${_TMPLOG}"
    echo "=== last 300 lines ==="
    tail -300 "${_TMPLOG}"
  else
    echo "=== FAILED — full output ==="
    cat "${_TMPLOG}"
  fi

  rm -f "${_TMPLOG}"
  _TMPLOG=""
  return ${exit_code}
}

collect_artifact() {
  local artifact
  artifact=$(ls envoy-alpha-*.tar.gz 2>/dev/null | head -1)
  [[ -z "${artifact}" ]] && { echo "ERROR: No envoy-alpha-*.tar.gz found" >&2; exit 1; }
  cp "${artifact}" "${TMT_TEST_DATA}/${artifact}"
  echo "Artifact: ${artifact} ($(du -sh "${artifact}" | cut -f1))"
}
