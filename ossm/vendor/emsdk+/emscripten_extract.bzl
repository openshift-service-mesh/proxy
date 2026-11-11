"""Extract a downloaded Emscripten release archive in a build action.

The release archives are large (~340MB compressed, ~1.5GB extracted) and
extracting them in the repository rule costs every fresh output base minutes of
single-threaded CPU before analysis can even start. Extracting in an action
instead makes the result a cacheable tree artifact: with remote execution the
archive is uploaded once and the extracted tree only ever lives on the workers.

Extraction uses the hermetic bsdtar from the tar.bzl toolchain (handles tar.xz
and zip), so nothing is required of the execution platform. The extracted tree
is pruned to what the toolchain actually uses, the same set as the filegroups
the http_archive build file used to declare; symlinks (clang -> clang-NN,
wasm-ld -> lld, node_modules/.bin/*) are kept, with their targets, as relative
links inside the trees.
"""

TAR_TOOLCHAIN_TYPE = "@tar.bzl//tar/toolchain:type"

# Paths under the archive prefix that are never needed.
EXCLUDE = [
    "emscripten/test",
    "emscripten/docs",
    "emscripten/media",
]

# Path components excluded wherever they occur.
EXCLUDE_ANYWHERE = ["__pycache__"]

def _emscripten_extract_impl(ctx):
    bin_dir = ctx.actions.declare_directory("bin")
    emscripten_dir = ctx.actions.declare_directory("emscripten")
    lib_dir = ctx.actions.declare_directory("lib")
    outputs = [bin_dir, emscripten_dir, lib_dir]
    bsdtar = ctx.toolchains[TAR_TOOLCHAIN_TYPE]
    prefix = ctx.attr.strip_prefix.strip("/")
    components = len(prefix.split("/")) if prefix else 0
    members = [
        "{}/{}".format(prefix, path) if prefix else path
        for path in ["bin/" + tool for tool in ctx.attr.bin_tools] + ["emscripten", "lib"]
    ]
    excludes = ["{}/{}".format(prefix, path) if prefix else path for path in EXCLUDE] + EXCLUDE_ANYWHERE

    args = ctx.actions.args()
    args.add("--extract")
    args.add("--file", ctx.file.archive)
    args.add("-C", bin_dir.dirname)
    args.add("--strip-components", str(components))
    args.add_all(excludes, before_each = "--exclude")
    args.add_all(members)
    ctx.actions.run(
        executable = bsdtar.tarinfo.binary,
        inputs = depset([ctx.file.archive], transitive = [bsdtar.default.files]),
        outputs = outputs,
        arguments = [args],
        mnemonic = "EmscriptenExtract",
        progress_message = "Extracting %s" % ctx.file.archive.short_path,
        toolchain = TAR_TOOLCHAIN_TYPE,
    )
    return [
        DefaultInfo(files = depset(outputs)),
        OutputGroupInfo(
            bin = depset([bin_dir]),
            emscripten = depset([emscripten_dir]),
            lib = depset([lib_dir]),
        ),
    ]

emscripten_extract = rule(
    implementation = _emscripten_extract_impl,
    attrs = {
        "archive": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "Downloaded Emscripten release archive (tar.xz or zip).",
        ),
        "bin_tools": attr.string_list(
            mandatory = True,
            doc = "Members of bin/ to extract (bsdtar patterns).",
        ),
        "strip_prefix": attr.string(
            doc = "Directory prefix to strip from the archive members.",
        ),
    },
    toolchains = [TAR_TOOLCHAIN_TYPE],
)
