licenses(["notice"])  # Apache 2

# Wraps system LLVM 21 installation for use by BoringSSL compatibility layer prefixer tool
# The prefixer needs LLVM/Clang headers to parse and transform OpenSSL headers

# All LLVM/Clang include files - be specific to avoid globbing non-LLVM files
# Include .h, .def, .inc, and .td files that Clang headers depend on
filegroup(
    name = "include",
    srcs = glob([
        "lib/clang/21/include/**/*.h",
        "include/clang/**/*.h",
        "include/clang/**/*.def",
        "include/clang/**/*.inc",
        "include/clang/**/*.td",
        "include/clang-c/**/*.h",
        "include/llvm/**/*.h",
        "include/llvm/**/*.def",
        "include/llvm/**/*.inc",
        "include/llvm/**/*.td",
        "include/llvm-c/**/*.h",
    ]),
    visibility = ["//visibility:public"],
)

# Alias for Envoy prefixer which expects all_includes
alias(
    name = "all_includes",
    actual = ":include",
    visibility = ["//visibility:public"],
)

# The prefixer needs LLVM/Clang libraries in two forms:
# 1. A filegroup for $(location) expressions in BUILD files
# 2. A cc_library for linking (deps)
# The maistra-builder container has libclang-cpp.so.21.1 at /usr/lib64/

# Filegroup for $(location) expressions - points to the actual .so file
filegroup(
    name = "lib/libclang-cpp.so.21.1",
    srcs = ["lib64/libclang-cpp.so.21.1"],
    visibility = ["//visibility:public"],
)

# cc_library for linking - provides both Clang and LLVM libraries
# The prefixer needs both: libclang-cpp.so (Clang symbols) and libLLVM.so (LLVM symbols)
cc_library(
    name = "llvm",
    srcs = [
        "lib64/libclang-cpp.so.21.1",
        "lib64/libLLVM.so.21.1",
    ],
    visibility = ["//visibility:public"],
    linkstatic = False,
)

# Compatibility alias for code expecting LLVM 18.1
alias(
    name = "lib/libclang-cpp.so.18.1",
    actual = "lib/libclang-cpp.so.21.1",
    visibility = ["//visibility:public"],
)

# LLVM binaries only - exclude non-LLVM tools
filegroup(
    name = "bin",
    srcs = glob([
        "bin/clang*",
        "bin/llvm*",
        "bin/lld*",
        "bin/ld.lld*",
    ]),
    visibility = ["//visibility:public"],
)

# LLVM libraries only - be specific to avoid copying everything
filegroup(
    name = "lib",
    srcs = glob([
        "lib64/libclang*.so*",
        "lib64/libLLVM*.so*",
        "lib64/liblld*.so*",
        "lib64/libLTO*.so*",
        "lib64/libRemarks*.so*",
    ]),
    visibility = ["//visibility:public"],
)
