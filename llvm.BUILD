licenses(["notice"])  # Apache 2 with LLVM Exception

# This BUILD file wraps the system LLVM installation (from Fedora RPM packages)
# System LLVM is installed via: clang21-devel, llvm21-devel, lld21, libcxx-devel
# Similar to how openssl.BUILD wraps system OpenSSL
#
# Repository path is "/usr", so paths below are relative to /usr:
# - bin/clang-21 resolves to /usr/bin/clang-21
# - lib64/clang/21/include/ resolves to /usr/lib64/clang/21/include/
#
# Note: The Dockerfile creates symlinks like /usr/bin/clang -> /usr/bin/clang-21

package(default_visibility = ["//visibility:public"])

# Clang compiler builtin headers (stddef.h, limits.h, etc.)
# Located at /usr/lib/clang/21/include/ on Fedora 43 (lib, not lib64!)
# Note: /lib is a symlink to usr/lib, so paths may appear as either /lib/clang or /usr/lib/clang
filegroup(
    name = "clang_builtin_headers",
    srcs = glob([
        "lib/clang/21/include/**/*.h",
        "lib/clang/21/include/**",
    ]),
)

# LLVM libraries
filegroup(
    name = "llvm_libs",
    srcs = glob([
        "lib64/llvm21/lib/*.so*",
        "lib64/llvm21/lib/*.a",
    ]),
)

# All LLVM/Clang includes
# Note: We use libc++ headers from LLVM 21 distribution (symlinked at /usr/include/c++/v1)
# instead of Fedora 43's libc++ which requires Clang 22+
filegroup(
    name = "include",
    srcs = glob([
        "lib64/llvm21/include/**",
        "lib/clang/21/include/**",     # Compiler builtin headers (stddef.h, limits.h, etc.)
        "include/c++/v1/**",            # libc++ headers compatible with Clang 21 (symlinked)
    ]),
)

# All files (for completeness) - limit scope to avoid scanning entire filesystem
filegroup(
    name = "all_files",
    srcs = [
        ":bin",
        ":include",
        ":llvm_libs",
        ":clang_builtin_headers",
    ],
)

# Compiler components needed by toolchain
filegroup(
    name = "compiler_components",
    srcs = [
        "bin/clang",      # Symlink created by Dockerfile: /usr/bin/clang -> /usr/bin/clang-21
        "bin/clang++",    # Symlink created by Dockerfile
        "bin/llvm-ar",    # Symlink created by Dockerfile
        "bin/llvm-nm",    # Symlink created by Dockerfile
        "bin/llvm-objcopy",
        "bin/llvm-objdump",
        "bin/llvm-strip",
        "bin/llvm-dwp",
        "bin/llvm-profdata",
        "bin/llvm-cov",
        "bin/lld",        # Symlink created by Dockerfile
        ":clang_builtin_headers",
        ":llvm_libs",
    ],
)

# Individual tool targets (using symlinks created by Dockerfile for simplicity)
filegroup(name = "clang", srcs = ["bin/clang"])
filegroup(name = "clang++", srcs = ["bin/clang++"])
filegroup(name = "llvm-ar", srcs = ["bin/llvm-ar"])
filegroup(name = "llvm-nm", srcs = ["bin/llvm-nm"])
filegroup(name = "llvm-objcopy", srcs = ["bin/llvm-objcopy"])
filegroup(name = "llvm-objdump", srcs = ["bin/llvm-objdump"])
filegroup(name = "llvm-strip", srcs = ["bin/llvm-strip"])
filegroup(name = "llvm-dwp", srcs = ["bin/llvm-dwp"])
filegroup(name = "llvm-profdata", srcs = ["bin/llvm-profdata"])
filegroup(name = "llvm-cov", srcs = ["bin/llvm-cov"])

# Additional tools for code quality (clang-tidy, clang-format, etc.)
# These may be in clang-tools-extra package
filegroup(name = "clang-cpp", srcs = ["bin/clang-cpp"])
filegroup(name = "clang-format", srcs = ["bin/clang-format"])
filegroup(name = "clang-tidy", srcs = ["bin/clang-tidy"])

# Linker
filegroup(name = "lld", srcs = ["bin/lld"])
filegroup(name = "ld.lld", srcs = ["bin/ld.lld"])
filegroup(name = "ld", srcs = ["bin/ld.lld"])

# Tool aliases without llvm- prefix (for compatibility)
filegroup(name = "as", srcs = ["bin/clang"])
filegroup(name = "ar", srcs = ["bin/llvm-ar"])
filegroup(name = "nm", srcs = ["bin/llvm-nm"])
filegroup(name = "objcopy", srcs = ["bin/llvm-objcopy"])
filegroup(name = "objdump", srcs = ["bin/llvm-objdump"])
filegroup(name = "strip", srcs = ["bin/llvm-strip"])
filegroup(name = "dwp", srcs = ["bin/llvm-dwp"])
filegroup(name = "profdata", srcs = ["bin/llvm-profdata"])
filegroup(name = "cov", srcs = ["bin/llvm-cov"])

# Additional toolchain helpers
# Only include LLVM/Clang tools, not all of /usr/bin/ (which has thousands of files
# including setuid binaries like sudoedit that Bazel can't read)
filegroup(
    name = "bin",
    srcs = [
        "bin/clang",
        "bin/clang++",
        "bin/clang-21",
        "bin/clang++-21",
        "bin/llvm-ar",
        "bin/llvm-ar-21",
        "bin/llvm-nm",
        "bin/llvm-nm-21",
        "bin/llvm-objcopy",
        "bin/llvm-objcopy-21",
        "bin/llvm-objdump",
        "bin/llvm-objdump-21",
        "bin/llvm-strip",
        "bin/llvm-strip-21",
        "bin/llvm-dwp",
        "bin/llvm-dwp-21",
        "bin/llvm-profdata",
        "bin/llvm-profdata-21",
        "bin/llvm-cov",
        "bin/llvm-cov-21",
        "bin/lld",
        "bin/lld-21",
        "bin/ld.lld",
        "bin/ld.lld-21",
        "bin/llvm-ranlib",
        "bin/llvm-ranlib-21",
        "bin/lld-link",
        "bin/lld-link-21",
        "bin/clang-cpp",
        "bin/clang-cpp-21",
        "bin/clang-format",
        "bin/clang-format-21",
        "bin/clang-tidy",
        "bin/clang-tidy-21",
    ],
)

filegroup(name = "lib", srcs = [":llvm_libs"])
filegroup(name = "lib_legacy", srcs = [":llvm_libs"])

# Config site (may be needed by toolchain)
filegroup(name = "extra_config_site", srcs = [])
