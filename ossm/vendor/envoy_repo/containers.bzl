

REPO = "docker.io/envoyproxy/envoy-build"
REPO_GCR = "gcr.io/envoy-ci/envoy-build"
SHA = "eaa30b863e9ab881e1bc34106788e4282b84313c3fef9bf50661923725331663"
SHA_GCC = "d4ca56020e17aa36d6baad8e172d09c8a08e47ed0a911b779400c645957fa220"
SHA_MOBILE = "d6b6eef676d426e38f15c8e675d4462194d5d267f1b469edf73cc6f2bf4c2ce2"
SHA_WORKER = "7d3c99085fa5f1cff6b7293de256cc6c93ce61cd7ccb63432113a1f8fbf12a43"
TAG = "v0.2.2"

def image_gcc():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_GCC)

def image_mobile():
    return "%s@sha256:%s" % (
        REPO, SHA_MOBILE)

def image_worker():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_WORKER)

