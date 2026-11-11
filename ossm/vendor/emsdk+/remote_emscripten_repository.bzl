load(":emscripten_build_file.bzl", "emscripten_build_file_content")
load(":revisions.bzl", "EMSCRIPTEN_TAGS")
load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")
load("//emscripten_toolchain:toolchain.bzl", "emscripten_cc_toolchain_config_rule")

def _python_exec_files_impl(ctx):
    return [DefaultInfo(files = ctx.attr.src[DefaultInfo].files)]

_python_exec_files = rule(
    implementation = _python_exec_files_impl,
    attrs = {"src": attr.label(cfg = "exec")},
)

def _emscripten_archive_impl(ctx):
    archive = "wasm-binaries.{}".format(ctx.attr.type)
    ctx.download(
        url = ctx.attr.url,
        output = archive,
        sha256 = ctx.attr.sha256,
    )
    ctx.file("WORKSPACE", 'workspace(name = "{}")\n'.format(ctx.name))
    ctx.file(
        "BUILD.bazel",
        emscripten_build_file_content(
            archive = archive,
            bin_extension = ctx.attr.bin_extension,
            strip_prefix = ctx.attr.strip_prefix,
        ),
    )

_emscripten_archive = repository_rule(
    implementation = _emscripten_archive_impl,
    attrs = {
        "bin_extension": attr.string(),
        "sha256": attr.string(mandatory = True),
        "strip_prefix": attr.string(),
        "type": attr.string(mandatory = True, values = ["tar.xz", "zip"]),
        "url": attr.string(mandatory = True),
    },
    doc = "Downloads an Emscripten release archive; it is extracted by a build action.",
)

def remote_emscripten_repository(
    name,
    bin_extension,
    **kwargs,
):
    """Imports an Emscripten from a release archive

    The archive is only downloaded by the repository rule; extraction happens
    in a build action (see emscripten_extract.bzl) so that it is cached and,
    with remote execution, never has to happen on the machine running Bazel.

    Args:
      name: A unique name for this Emscripten repository.
      bin_extension: Extension for the binaries in this Emscripten repository
      **kwargs: url, sha256, type and strip_prefix of the archive.
    """
    _emscripten_archive(
        name = name,
        bin_extension = bin_extension,
        **kwargs
    )

def emscripten_toolchain_name(name):
    return "emscripten_{}".format(name)

def _get_name_and_target(name):
    return name, ":" + name

def create_toolchains(name, repo_name, exec_compatible_with):
    """Creates toolchain definition for an Emscripten

    Register the toolchains defined by this macro via
    `register_toolchains("//<path-to-target>:cc-toolchain-wasm-<name>")`

    Args:
      name: A unique name for this Emscripten toolchain
      repo_name: The name of the Emscripten repository for this toolchain
      exec_compatible_with: Execute platform constraints for the Emscripten toolchain associated
        with this repository.
      **kwargs: Args for http_archive. Refer to http_archive documentation for more info.
    """
    common_files_name, common_files_target = _get_name_and_target("common_files_" + name)
    compiler_files_name, compiler_files_target = _get_name_and_target("compiler_files_" + name)
    linker_files_name, linker_files_target = _get_name_and_target("linker_files_" + name)
    ar_files_name, ar_files_target = _get_name_and_target("ar_files_" + name)
    all_files_name, all_files_target = _get_name_and_target("all_files_" + name)
    cc_wasm_name, cc_wasm_target = _get_name_and_target("cc-compiler-wasm-" + name)

    wasm_name = "wasm-" + name

    # These are file groups defined by the build_file_content on the Emscripten http_archive
    remote_repo = "@{}//".format(repo_name)
    repo_compiler_files_target = remote_repo + ":compiler_files"
    repo_linker_files_target = remote_repo + ":linker_files"
    repo_ar_files_target = remote_repo + ":ar_files"

    python_exec_name = "python_exec_files_" + name
    _python_exec_files(
        name = python_exec_name,
        src = "@python_3_12//:files",
    )

    native.filegroup(
        name = common_files_name,
        srcs = [
            "@emscripten_cache//:emscripten_config",
            "@emsdk//emscripten_toolchain:env.sh",
            "@emsdk//emscripten_toolchain:env.bat",
            "@nodejs//:node_files",
            ":" + python_exec_name,
        ],
    )

    native.filegroup(
        name = compiler_files_name,
        srcs = [
            "@emsdk//emscripten_toolchain:emcc.sh",
            "@emsdk//emscripten_toolchain:emcc.bat",
            repo_compiler_files_target,
            common_files_target,
        ],
    )

    native.filegroup(
        name = linker_files_name,
        srcs = [
            "@emsdk//emscripten_toolchain:emcc_link.sh",
            "@emsdk//emscripten_toolchain:emcc_link.bat",
            "link_wrapper.py",
            repo_linker_files_target,
            common_files_target,
        ],
    )

    native.filegroup(
        name = ar_files_name,
        srcs = [
            "@emsdk//emscripten_toolchain:emar.sh",
            "@emsdk//emscripten_toolchain:emar.bat",
            repo_ar_files_target,
            common_files_target,
        ],
    )

    native.filegroup(
        name = all_files_name,
        srcs = [
            ar_files_target,
            compiler_files_target,
            linker_files_target,
        ],
    )

    normalized_exec_compatible_with = [Label(str(constraint)) for constraint in exec_compatible_with]
    is_windows_exec_platform = (
        Label("@platforms//os:windows") in normalized_exec_compatible_with or
        name.endswith("_win")
    )

    emscripten_cc_toolchain_config_rule(
        name = wasm_name,
        cpu = "wasm",
        em_config = "@emscripten_cache//:emscripten_config",
        emscripten_binaries = repo_compiler_files_target,
        nodejs_bin = "@nodejs//:node",
        python_bin = "@python_3_12//:files",
        script_extension = "bat" if is_windows_exec_platform else "sh",
    )

    cc_toolchain(
        name = cc_wasm_name,
        all_files = all_files_target,
        ar_files = ar_files_target,
        as_files = ":empty",
        compiler_files = compiler_files_target,
        dwp_files = ":empty",
        linker_files = linker_files_target,
        objcopy_files = ":empty",
        strip_files = ":empty",
        toolchain_config = wasm_name,
        toolchain_identifier = "emscripten-wasm-" + name,
    )

    native.toolchain(
        name = "cc-toolchain-wasm-" + name,
        target_compatible_with = ["@platforms//cpu:wasm32"],
        exec_compatible_with = exec_compatible_with,
        toolchain = cc_wasm_target,
        toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
    )

    cc_toolchain_suite(
        name = "everything-" + name,
        toolchains = {
            "wasm": cc_wasm_target,
            "wasm|emscripten": cc_wasm_target,
        },
    )
