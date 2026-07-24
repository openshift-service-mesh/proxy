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
cleanup_container() { podman rm -f "${CNAME}" 2>/dev/null || true; }
trap cleanup_container EXIT

podman run -d --name "${CNAME}" --privileged \
  -e CI=true \
  -e LOCAL_JOBS="${LOCAL_JOBS}" \
  -e LOCAL_CPU_RESOURCES="$(nproc)" \
  -e LOCAL_RAM_RESOURCES="${LOCAL_RAM}" \
  -v "$(pwd)":/work:z -w /work \
  "$(cat ossm/ci/builder-image)" \
  sleep infinity
