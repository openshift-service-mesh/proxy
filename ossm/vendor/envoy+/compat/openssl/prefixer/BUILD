load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//bazel:toolchains.bzl", "LIBCLANG_CPP", "LIBLLVM")

licenses(["notice"])  # Apache 2

# OSSM: use the host LLVM toolchain's libstdc++ headers and static runtime.
# The hermetic GCC runtime is unavailable on s390x and ppc64le.
cc_binary(
    name = "prefixer",
    srcs = ["prefixer.cpp"],
    additional_linker_inputs = [
        LIBCLANG_CPP,
    ] + ([LIBLLVM] if LIBLLVM else []),
    copts = [
        "-fno-rtti",  # Required by libclang-cpp
        # Use the host libstdc++ for ABI compatibility with libclang-cpp.
        "-stdlib=libstdc++",
    ],
    linkopts = [
        "$(location " + LIBCLANG_CPP + ")",
    ] + (["$(location " + LIBLLVM + ")"] if LIBLLVM else []) + [
        "-Wl,-rpath,$$ORIGIN/../lib",
        # The host toolchain supplies the static libstdc++ runtime.
        "-stdlib=libstdc++",
    ],
    visibility = ["//visibility:public"],
    deps = ["@llvm_toolchain_llvm//:clang_tooling_headers"],
)
