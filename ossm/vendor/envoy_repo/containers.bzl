

REPO = "docker.io/envoyproxy/envoy-build"
REPO_GCR = "gcr.io/envoy-ci/envoy-build"
SHA = "0b285a2c5e8fd85db238a6159f9748dac38569f081501bd508876076fecc3fe5"
SHA_GCC = "61d798d4385162ba52b7f80316a15bea096feaa255e61365f842e9902843d6c4"
SHA_MOBILE = "a80317cd73e52bea46caa2fd7d12142f2afdaca372a903523e42b00bc5266680"
SHA_WORKER = "936a89f86a2dff47a2027031a7c330e97eb05339c93d6742b0a2d9adc6680a12"
TAG = "v0.1.6"

def image_gcc():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_GCC)

def image_mobile():
    return "%s@sha256:%s" % (
        REPO, SHA_MOBILE)

def image_worker():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_WORKER)

