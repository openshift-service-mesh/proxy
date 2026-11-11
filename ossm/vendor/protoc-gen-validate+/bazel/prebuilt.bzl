"""Prebuilt protoc-gen-validate binaries from the upstream GitHub release.

Building the plugin from source drags the Go toolchain, gazelle (compiled on
the fly by `go_repository_tools`) and the plugin's Go dependencies into every
build that generates validators, which is most of them. The release ships
static binaries for every platform Bazel runs on, so the plugin is downloaded
instead; the Go rules are only loaded by the packages that really need them.
"""

PREBUILT_VERSION = "1.3.3"

_URL = "https://github.com/bufbuild/protoc-gen-validate/releases/download/v{version}/protoc-gen-validate_{version}_{platform}.tar.gz"

# sha256 of the release archives, from protoc-gen-validate_<version>_checksums.txt.
PREBUILT_PLATFORMS = {
    "darwin_amd64": struct(
        sha256 = "10090dc4e2a58d9c4392482677add96a4f4273df76a536da27aec2ea5417df89",
        binary = "protoc-gen-validate",
        constraints = ["@platforms//os:macos", "@platforms//cpu:x86_64"],
    ),
    "darwin_arm64": struct(
        sha256 = "0ae7bb4cdc6eb357e721db8f8f9b07b10a87fcb234899704d4eab33ee2b793ee",
        binary = "protoc-gen-validate",
        constraints = ["@platforms//os:macos", "@platforms//cpu:aarch64"],
    ),
    "linux_amd64": struct(
        sha256 = "6f851d3636b0c12a9fb5f99bf5c57651319f6a4c1d695f304269f1204dc9e13c",
        binary = "protoc-gen-validate",
        constraints = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    ),
    "linux_arm64": struct(
        sha256 = "e34b7526405741d7fafbf6f1c68cdda429b9420190b180a0b023016651215190",
        binary = "protoc-gen-validate",
        constraints = ["@platforms//os:linux", "@platforms//cpu:aarch64"],
    ),
    "windows_amd64": struct(
        sha256 = "f4695fc6c243357dc0ef90fea630c15ef04aa2d4ce4343873056183095658f88",
        binary = "protoc-gen-validate.exe",
        constraints = ["@platforms//os:windows", "@platforms//cpu:x86_64"],
    ),
}

def prebuilt_repo_name(platform):
    return "protoc_gen_validate_prebuilt_" + platform

def _prebuilt_repository_impl(ctx):
    ctx.download_and_extract(
        url = _URL.format(version = ctx.attr.version, platform = ctx.attr.platform),
        sha256 = ctx.attr.sha256,
    )
    ctx.file("WORKSPACE", 'workspace(name = "{}")\n'.format(ctx.name))
    ctx.file("BUILD.bazel", 'exports_files(["{}"])\n'.format(ctx.attr.binary))

_prebuilt_repository = repository_rule(
    implementation = _prebuilt_repository_impl,
    attrs = {
        "binary": attr.string(mandatory = True),
        "platform": attr.string(mandatory = True),
        "sha256": attr.string(mandatory = True),
        "version": attr.string(mandatory = True),
    },
    doc = "Downloads the protoc-gen-validate release archive for one platform.",
)

def _prebuilt_impl(_module_ctx):
    for platform, info in PREBUILT_PLATFORMS.items():
        _prebuilt_repository(
            name = prebuilt_repo_name(platform),
            binary = info.binary,
            platform = platform,
            sha256 = info.sha256,
            version = PREBUILT_VERSION,
        )

prebuilt = module_extension(
    implementation = _prebuilt_impl,
    doc = "Repositories holding the prebuilt protoc-gen-validate binaries, one per platform.",
)

def _prebuilt_binary_impl(ctx):
    binary = ctx.file.binary
    extension = "." + binary.extension if binary.extension else ""
    out = ctx.actions.declare_file(ctx.label.name + extension)
    ctx.actions.symlink(output = out, target_file = binary, is_executable = True)
    return [DefaultInfo(
        executable = out,
        files = depset([out]),
        runfiles = ctx.runfiles(files = [out]),
    )]

prebuilt_binary = rule(
    implementation = _prebuilt_binary_impl,
    attrs = {
        "binary": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "The prebuilt binary for the platform this target is built for (a select).",
        ),
    },
    executable = True,
    doc = "An executable target wrapping a prebuilt binary, usable wherever a go_binary was.",
)
