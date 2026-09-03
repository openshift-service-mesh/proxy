set -euo pipefail

CNAME="ossm-hermetic-$$"
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Phase 1: Pre-fetch dependencies with network (like Cachi2 in Konflux)
run_in_podman "go mod download"

# Phase 2: Disconnect network (like unshare --net in Konflux)
for net in $(podman inspect "${CNAME}" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}'); do
  podman network disconnect --force "${net}" "${CNAME}"
done

if podman exec "${CNAME}" curl -s --connect-timeout 3 https://github.com > /dev/null 2>&1; then
  echo "ERROR: container still has network access after disconnect" >&2
  exit 1
fi
echo "Network disconnected: container is now isolated"

# Phase 3: Full build without network (replicates Konflux hermetic build)
run_in_podman "GOPROXY=off bash ossm/ci/pre-submit.sh"

echo "Hermetic build passed: all dependencies are available offline"
