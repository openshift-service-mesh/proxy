

REPO = "docker.io/envoyproxy/envoy-build"
REPO_GCR = "gcr.io/envoy-ci/envoy-build"
SHA = "8fdf16ea0d40cb0e4726b13f97df8b73e80e331b206b62b224ceb2498149a1d5"
SHA_GCC = "ca3b98402aa2bb59f44d2b5ff8fc8ccbcedc623dad539ca1a15866762854721a"
SHA_MOBILE = "b4351554fbf60ecf5b69ae17434a1503802473118388361543a3c695040f8859"
SHA_WORKER = "58abaea3f29aae5340f32dc99fc66c97a6c2fec0902345d03cf6d47684606a1d"
TAG = "7e0344e0ddd6ee5e56105172f7dd17346049c0df"

def image_gcc():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_GCC)

def image_mobile():
    return "%s@sha256:%s" % (
        REPO, SHA_MOBILE)

def image_worker():
    return "%s@sha256:%s" % (
        REPO_GCR, SHA_WORKER)

