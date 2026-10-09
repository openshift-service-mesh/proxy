

REPO = "docker.io/envoyproxy/envoy-build"
REPO_GCR = "gcr.io/envoy-ci/envoy-build"
SHA = "0ec8c3295229234f5a5663b858d9e217fd409e2eba22afe7a9c6e4f634bd7ea8"
SHA_GCC = "66e7359c8dcc148ce12d0828e9547d7f29900b788b22b4c804dab664f724ad35"
SHA_MOBILE = "ab4cb76a32f7fae2e3bfdfe1f1fd632897baa952334a5f9805107ed5f1233687"
SHA_WORKER = "c531dd07f0755d990167f6d495f6b199ad399f8ca660887785b022da2d5b3031"
TAG = "v0.2.4"

def image_gcc():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_GCC)

def image_mobile():
    return "%s@sha256:%s" % (
        REPO, SHA_MOBILE)

def image_worker():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_WORKER)

