"""A templated build file for emscripten repositories"""

# The tools the toolchain uses, i.e. the files the filegroups below used to
# list individually from an extracted http_archive, plus the targets of the
# symlinks among them (clang -> clang-NN, wasm-ld -> lld). Everything else
# under bin/ is left out of the extracted tree.
EMSCRIPTEN_BIN_TOOLS = [
    "clang",
    "clang++",
    "clang-[0-9]*",
    "lld",
    "llvm-ar",
    "llvm-dwarfdump",
    "llvm-dwp",
    "llvm-nm",
    "llvm-objcopy",
    "wasm-ctor-eval",
    "wasm-emscripten-finalize",
    "wasm-ld",
    "wasm-metadce",
    "wasm-opt",
    "wasm-split",
    "wasm2js",
]

EMSCRIPTEN_BUILD_FILE_CONTENT_TEMPLATE = """
load("@emsdk//:emscripten_extract.bzl", "emscripten_extract")

package(default_visibility = ['//visibility:public'])

emscripten_extract(
    name = "extract",
    archive = "{archive}",
    bin_tools = {bin_tools},
    strip_prefix = "{strip_prefix}",
)

filegroup(
    name = "bin",
    srcs = [":extract"],
    output_group = "bin",
)

filegroup(
    name = "emscripten",
    srcs = [":extract"],
    output_group = "emscripten",
)

filegroup(
    name = "lib",
    srcs = [":extract"],
    output_group = "lib",
)

filegroup(
    name = "all",
    srcs = [
        ":bin",
        ":emscripten",
        ":lib",
    ],
)

filegroup(
    name = "includes",
    srcs = [
        ":emscripten",
        ":lib",
    ],
)

filegroup(
    name = "emcc_common",
    srcs = [":emscripten"],
)

filegroup(
    name = "compiler_files",
    srcs = [
        ":bin",
        ":emscripten",
        ":lib",
    ],
)

filegroup(
    name = "linker_files",
    srcs = [
        ":bin",
        ":emscripten",
    ],
)

filegroup(
    name = "ar_files",
    srcs = [
        ":bin",
        ":emscripten",
    ],
)

filegroup(
    name = "dwp_files",
    srcs = [":bin"],
)
"""

def emscripten_build_file_content(archive, bin_extension, strip_prefix):
    return EMSCRIPTEN_BUILD_FILE_CONTENT_TEMPLATE.format(
        archive = archive,
        bin_tools = repr([tool + bin_extension for tool in EMSCRIPTEN_BIN_TOOLS]),
        strip_prefix = strip_prefix,
    )
