

REPO = "docker.io/envoyproxy/envoy-build"
REPO_GCR = "gcr.io/envoy-ci/envoy-build"
SHA = "4bee2c190e816d47ccb992d17c2c8c3f96815f79dcba5c207cbdf3b0e2510041"
SHA_GCC = "08924bde058f9d4254dfc53e1b7d22767ae1bac7fb005c0db1ef3b289b0b5c2f"
SHA_MOBILE = "f8807abfea33717aadb61ef6d5756332917409043a61a4f0fd19abb4986d548f"
SHA_WORKER = "1714d9c81bd61b493f24ae796b74db685f34cebdff6c3bb27c0cac6c683df66a"
TAG = "v0.1.10"

def image_gcc():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_GCC)

def image_mobile():
    return "%s@sha256:%s" % (
        REPO, SHA_MOBILE)

def image_worker():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_WORKER)

