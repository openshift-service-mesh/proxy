

REPO = "docker.io/envoyproxy/envoy-build"
REPO_GCR = "gcr.io/envoy-ci/envoy-build"
SHA = "fed53e3048bfc6bacaa02557d30fad43780ab610dfe70049796ce0a21744df85"
SHA_GCC = "342d7eaccb753e8efb2aa171dccfd3bd7e531a22730ecb72372ab64c5967681b"
SHA_MOBILE = "8652a1160c71fee4a18c1a044d195bcb0b9d75b10b1189c089a8fe24b78117b1"
SHA_WORKER = "934b50777b1eb9348b0e62cafd9eee5c79828e57d4ca08083c86d3099b14bb42"
TAG = "v0.1.8"

def image_gcc():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_GCC)

def image_mobile():
    return "%s@sha256:%s" % (
        REPO, SHA_MOBILE)

def image_worker():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_WORKER)

