load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# A future bump only needs to touch this dict: bump `VERSION`/`RELEASE`, and
# fill in the sha256 for each platform's tarball from the release's
# `checksums.txt.asc` (re-hash the downloaded tarball and use that value,
# rather than trusting the file contents blindly).
VERSION = "1.4.0"
RELEASE = "bins-v0.2.15"
URL_TEMPLATE = "https://github.com/envoyproxy/toolshed/releases/download/{release}/sq-{version}-{platform}.tar.zst"

PREBUILTS = {
    "linux_x86_64": struct(
        platform = "Linux-X64",
        sha256 = "dcef2a3f6ca8090684fdcbad777acbec83c9f6b182e2dca0288b06aa30b938a0",
    ),
    "linux_aarch64": struct(
        platform = "Linux-ARM64",
        sha256 = "ccdbe4a6c79c589a12d6a2eff3fe8f635e7b170a45bf947971c47a018e923ebd",
    ),
}

def _sq_prebuilt_impl(module_ctx):
    for name, prebuilt in PREBUILTS.items():
        http_archive(
            name = "sq_prebuilt_%s" % name,
            urls = [URL_TEMPLATE.format(release = RELEASE, version = VERSION, platform = prebuilt.platform)],
            sha256 = prebuilt.sha256,
            strip_prefix = "sq-%s-%s" % (VERSION, prebuilt.platform),
            # The URL ends in `.tar.zst`; `type` must be set explicitly since
            # it can't be inferred from a `download_and_extract` release URL
            # without an obvious archive suffix on some Bazel versions.
            # Supported by Bazel's `http_archive` since Bazel 6.
            type = "tar.zst",
        )

sq_prebuilt = module_extension(implementation = _sq_prebuilt_impl)
