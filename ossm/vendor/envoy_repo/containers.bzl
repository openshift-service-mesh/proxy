

REPO = "docker.io/envoyproxy/envoy-build"
REPO_GCR = "gcr.io/envoy-ci/envoy-build"
SHA = "0fa203f090138434505a5f1269a8d2bb4a47b885facb4ef5e6dc0c9f861d2aba"
SHA_GCC = "990d51067b5d2c23988a058a653605983216a6fe128feecd44d389e60a83b54e"
SHA_MOBILE = "f5b988fc8b80be5c0e439981d681fe2a25afef147b397d5d8799a6eb0274cd67"
SHA_WORKER = "382f86d26825767ce9cf68dd168e23728863792af1b81f73afcb14a38a586016"
TAG = "v0.2.3"

def image_gcc():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_GCC)

def image_mobile():
    return "%s@sha256:%s" % (
        REPO, SHA_MOBILE)

def image_worker():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_WORKER)

