set -euo pipefail

CNAME="ossm-release-$$"
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

run_in_podman "SKIP_GCS_UPLOAD=true bash ossm/ci/post-submit.sh"
collect_artifact
