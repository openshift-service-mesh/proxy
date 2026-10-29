load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//bazel:toolchains.bzl", "LIBCLANG_CPP", "LIBLLVM")

licenses(["notice"])  # Apache 2

# OSSM: build the prefixer against the host clang toolchain's libstdc++.
#
# Upstream sources libstdc++ from envoy_toolshed's libstdcxx sysroot, whose repo
# name and paths are hardcoded to linux_amd64 / x86_64-linux-gnu. OSSM builds this
# exec-config tool with the host toolchain (@llvm_host), which already provides a
# full host libstdc++ for the build arch (linked statically via the toolchain's
# stdlib="stdc++" setting) -- the same libstdc++ the rest of the //:envoy compile
# uses. Keeping the amd64 sysroot breaks the aarch64 build ("libstdc++.a ... is
# incompatible with elf64-littleaarch64"), so we drop that plumbing entirely.
cc_binary(
    name = "prefixer",
    srcs = ["prefixer.cpp"],
    additional_linker_inputs = [
        LIBCLANG_CPP,
    ] + ([LIBLLVM] if LIBLLVM else []),
    copts = [
        "-fno-rtti",  # Required by libclang-cpp
        # Use libstdc++ for ABI compatibility with libclang-cpp
        "-stdlib=libstdc++",
    ],
    linkopts = [
        "$(location " + LIBCLANG_CPP + ")",
    ] + (["$(location " + LIBLLVM + ")"] if LIBLLVM else []) + [
        "-Wl,-rpath,$$ORIGIN/../lib",
        # Use libstdc++ for ABI compatibility with libclang-cpp
        "-stdlib=libstdc++",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@llvm_toolchain_llvm//:clang_tooling_headers",
    ],
)
