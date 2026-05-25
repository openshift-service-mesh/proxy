#!/bin/bash
# Apply necessary fixes to vendored dependencies for Fedora 43 build compatibility
# Run this script after ossm/vendor is regenerated
#
# Note: LLVM toolchain configuration is handled by setting BAZEL_LLVM_PATH=/usr
# in update-deps.sh, which tells toolchains_llvm to use system LLVM with absolute
# paths. This eliminates the need for symlinks, exports_files, and path patches.

set -e

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

echo "Applying build fixes to vendored dependencies..."

# Fix 1: Apply Python3 genrule patch to Envoy
echo "  - Applying Python3 genrule patch to Envoy..."
ENVOY_VERSION_BUILD="ossm/vendor/envoy/source/common/version/BUILD"
if [ -f "$ENVOY_VERSION_BUILD" ] && grep -q 'PYPATH=\$\$(realpath \$\$(dirname \$(PYTHON3)))' "$ENVOY_VERSION_BUILD"; then
    cd "$ROOT_DIR/ossm/vendor/envoy"
    patch -p1 < "$ROOT_DIR/ossm/patches/fix-python3-genrule.patch" || echo "    Patch already applied or failed"
    cd "$ROOT_DIR"
    echo "    Envoy Python3 genrule patched"
else
    echo "    Envoy Python3 genrule already patched or file not found"
fi

# Fix 2: Fix PYTHON3 reference in cryptomb BUILD file
echo "  - Fixing cryptomb PYTHON3 reference..."
CRYPTOMB_FILE="ossm/vendor/envoy/contrib/cryptomb/private_key_providers/source/BUILD"
if [ -f "$CRYPTOMB_FILE" ] && grep -q '\$\$EXT_BUILD_ROOT/\$(PYTHON3)' "$CRYPTOMB_FILE"; then
    sed -i 's|\$\$EXT_BUILD_ROOT/\$(PYTHON3)|/usr/bin/python3|g' "$CRYPTOMB_FILE"
    echo "    cryptomb fixed"
else
    echo "    cryptomb already fixed or file not found"
fi

# Fix 3: Fix PYTHON3 reference in foreign_cc BUILD file
echo "  - Fixing foreign_cc PYTHON3 reference..."
FOREIGN_CC_FILE="ossm/vendor/envoy/bazel/foreign_cc/BUILD"
if [ -f "$FOREIGN_CC_FILE" ] && grep -q '\$\$EXT_BUILD_ROOT/\$(PYTHON3)' "$FOREIGN_CC_FILE"; then
    sed -i 's|\$\$EXT_BUILD_ROOT/\$(PYTHON3)|/usr/bin/python3|g' "$FOREIGN_CC_FILE"
    echo "    foreign_cc fixed"
else
    echo "    foreign_cc already fixed or file not found"
fi

# Fix 4: Fix PYTHON3 reference in hyperscan BUILD file
echo "  - Fixing hyperscan PYTHON3 reference..."
HYPERSCAN_FILE="ossm/vendor/envoy/contrib/hyperscan/matching/input_matchers/source/BUILD"
if [ -f "$HYPERSCAN_FILE" ] && grep -q '\$(PYTHON3)' "$HYPERSCAN_FILE"; then
    sed -i 's|\$(PYTHON3)|/usr/bin/python3|g' "$HYPERSCAN_FILE"
    echo "    hyperscan fixed"
else
    echo "    hyperscan already fixed or file not found"
fi

# Fix 5: Remove PYTHON3 make variable from V8
echo "  - Fixing V8 PYTHON3 genrule..."
V8_FILE="ossm/vendor/v8/BUILD.bazel"
if [ -f "$V8_FILE" ] && grep -q 'export PATH=\$\$(dirname \$\$(realpath \$(PYTHON3))):\$\$PATH' "$V8_FILE"; then
    sed -i '/export PATH=\$\$(dirname \$\$(realpath \$(PYTHON3))):\$\$PATH/d' "$V8_FILE"
    echo "    V8 fixed"
else
    echo "    V8 already fixed or file not found"
fi

# Fix 6: Fix luajit configure command
echo "  - Fixing luajit configure command..."
ENVOY_BUILD="ossm/vendor/envoy/bazel/foreign_cc/BUILD"
if [ -f "$ENVOY_BUILD" ] && grep -q 'configure_command = "build.py"' "$ENVOY_BUILD"; then
    sed -i 's/configure_command = "build.py"/configure_command = "luajit_build.sh"/' "$ENVOY_BUILD"
    echo "    luajit configure command fixed"
else
    echo "    luajit already fixed or file not found"
fi

# Fix 7: Add system compiler overrides to Envoy foreign_cc CMake targets
echo "  - Adding system compiler overrides to Envoy foreign_cc BUILD..."

if [ -f "$ENVOY_BUILD" ] && grep -q '"CMAKE_C_COMPILER": "/usr/bin/clang"' "$ENVOY_BUILD"; then
    echo "    Already patched, skipping"
else
    echo "    Applying patches..."

    python3 << 'EOFPYTHON'
import re

BUILD_FILE = "ossm/vendor/envoy/bazel/foreign_cc/BUILD"

with open(BUILD_FILE, "r") as f:
    content = f.read()

compiler_flags = '''        # Force use of system compiler and sysroot instead of vendored LLVM toolchain
        "CMAKE_C_COMPILER": "/usr/bin/clang",
        "CMAKE_CXX_COMPILER": "/usr/bin/clang++",
        "CMAKE_C_FLAGS": "--sysroot=/",
        "CMAKE_CXX_FLAGS": "--sysroot=/ -stdlib=libc++",
        "CMAKE_EXE_LINKER_FLAGS": "--sysroot=/ -fuse-ld=/usr/bin/ld.lld",
'''

targets = [
    (r'(name = "libsxg".*?cache_entries = \{[^}]+)(\n\s+\},)',
     r'\1\n' + compiler_flags + r'\2'),
    (r'("_GNU_SOURCE": "on",)(\n\s+\},\n\s+exec_properties)',
     r'\1\n' + compiler_flags + r'\2'),
    (r'("CMAKE_CXX_COMPILER_FORCED": "on",)(\n\s+\},\n\s+cmake_files_dir)',
     r'\1\n' + compiler_flags + r'\2'),
    (r'("WAMR_BUILD_LINUX_PERF": "0",)(\n\s+\},\n\s+exec_properties)',
     r'\1\n' + compiler_flags + r'\2'),
    (r'("BUILD_TESTING": "off",)(\n\s+\},\n\s+defines)',
     r'\1\n' + compiler_flags + r'\2'),
]

for pattern, replacement in targets:
    content = re.sub(pattern, replacement, content, count=1, flags=re.DOTALL)

with open(BUILD_FILE, "w") as f:
    f.write(content)

print("    Patching complete")
EOFPYTHON
fi

# Fix 8: Update llvm_version in vendored envoy toolchains.bzl to match system Clang
echo "  - Updating llvm_version to match system Clang..."
TOOLCHAINS_BZL="ossm/vendor/envoy/bazel/toolchains.bzl"
if [ -f "$TOOLCHAINS_BZL" ]; then
    if grep -q 'llvm_version = "18.1.8"' "$TOOLCHAINS_BZL"; then
        sed -i 's/llvm_version = "18.1.8"/llvm_version = "21.1.8"/' "$TOOLCHAINS_BZL"
        echo "    Updated llvm_version from 18.1.8 to 21.1.8"
    else
        echo "    llvm_version already updated or different version found"
    fi
else
    echo "    Warning: toolchains.bzl not found"
fi

# Fix 8b: Fix cxx_builtin_include_directories in vendored llvm_toolchain
# toolchains_llvm generates paths with %workspace% prefix (e.g. %workspace%//usr/lib/clang/18/include)
# which resolve to <execroot>/usr/... instead of /usr/... — Bazel's include checker rejects them.
# We need to: (1) update clang/18 -> clang/21, (2) add absolute paths without %workspace%,
# and (3) remove Ubuntu/Debian-style paths that don't exist on Fedora.
echo "  - Fixing cxx_builtin_include_directories in llvm_toolchain..."
LLVM_TOOLCHAIN_BUILD="ossm/vendor/llvm_toolchain/BUILD.bazel"
if [ -f "$LLVM_TOOLCHAIN_BUILD" ]; then
    # Update Clang 18 paths to Clang 21 in %workspace%-prefixed entries
    if grep -q 'clang/18' "$LLVM_TOOLCHAIN_BUILD"; then
        sed -i 's|clang/18\.1\.8|clang/21.1.8|g; s|clang/18|clang/21|g' "$LLVM_TOOLCHAIN_BUILD"
        echo "    Updated Clang 18 paths to Clang 21"
    fi

    # Remove paths that don't exist on Fedora (cause module map 'umbrella directory not found' warnings):
    # - %workspace%//usr/include/x86_64-unknown-linux-gnu/c++/v1 (Ubuntu/Debian libc++ layout)
    # - %workspace%//usr/lib64/clang/*/include (Fedora uses /usr/lib/clang, not /usr/lib64/clang)
    sed -i 's|, "[^"]*x86_64-unknown-linux-gnu/c++/v1"||g' "$LLVM_TOOLCHAIN_BUILD"
    sed -i 's|, "[^"]*lib64/clang/[^"]*"||g' "$LLVM_TOOLCHAIN_BUILD"
    echo "    Removed non-existent Fedora include paths from cxx_builtin_include_directories"

    # Add absolute paths (without %workspace%) for Bazel's include checker
    # The %workspace%//usr/... paths don't resolve correctly to /usr/...
    if ! grep -q '"/usr/lib/clang/21/include", "/usr/include"' "$LLVM_TOOLCHAIN_BUILD"; then
        sed -i 's|"/usr/include", "/usr/local/include"|"/usr/lib/clang/21/include", "/usr/include", "/usr/local/include"|g' "$LLVM_TOOLCHAIN_BUILD"
        echo "    Added /usr/lib/clang/21/include to cxx_builtin_include_directories"
    else
        echo "    /usr/lib/clang/21/include already in cxx_builtin_include_directories"
    fi
else
    echo "    Warning: llvm_toolchain/BUILD.bazel not found"
fi

# Fix 9: Configure rules_foreign_cc to use preinstalled tools instead of bootstrapping
echo "  - Configuring rules_foreign_cc to use preinstalled tools..."
DEPENDENCY_IMPORTS="ossm/vendor/envoy/bazel/dependency_imports.bzl"
if [ -f "$DEPENDENCY_IMPORTS" ]; then
    if grep -q "rules_foreign_cc_dependencies()" "$DEPENDENCY_IMPORTS"; then
        perl -i -pe 's/rules_foreign_cc_dependencies\(\)/rules_foreign_cc_dependencies(\n        register_built_tools = False,\n        register_preinstalled_tools = True,\n    )/g' "$DEPENDENCY_IMPORTS"
        echo "    Configured rules_foreign_cc to use preinstalled tools"
    else
        echo "    rules_foreign_cc already configured for preinstalled tools"
    fi
else
    echo "    Warning: dependency_imports.bzl not found"
fi

# Fix 10: Add missing prebuilt_one_version target to remote_java_tools
echo "  - Adding missing prebuilt_one_version target to remote_java_tools..."
for java_tools_dir in ossm/vendor/remote_java_tools*; do
    if [ -d "$java_tools_dir" ]; then
        REMOTE_JAVA_TOOLS_BUILD="${java_tools_dir}/BUILD"
        if [ -f "$REMOTE_JAVA_TOOLS_BUILD" ]; then
            if ! grep -q "prebuilt_one_version" "$REMOTE_JAVA_TOOLS_BUILD"; then
                cat >> "$REMOTE_JAVA_TOOLS_BUILD" << 'EOF'

# Added by apply-build-fixes.sh to satisfy rules_java toolchain requirements
filegroup(
    name = "prebuilt_one_version",
    srcs = [],
)
EOF
                echo "    Added prebuilt_one_version target to $(basename ${java_tools_dir})/BUILD"
            else
                echo "    prebuilt_one_version already exists in $(basename ${java_tools_dir})/BUILD"
            fi
        fi
    fi
done

# Fix 11: Conditionally register system JDK as Java runtime toolchain
echo "  - Checking Java runtime toolchain configuration..."
WORKSPACE_FILE="WORKSPACE"
if [ -d "/usr/lib/jvm/java-21-openjdk" ]; then
    if ! grep -q 'name = "local_jdk"' "$WORKSPACE_FILE"; then
        cat >> "$WORKSPACE_FILE" << 'JDKEOF'

# System JDK for Java-based build tools (ANTLR4 in cel-cpp, etc.)
# Added conditionally by apply-build-fixes.sh when building in container
new_local_repository(
    name = "local_jdk",
    path = "/usr/lib/jvm/java-21-openjdk",
    build_file_content = """
package(default_visibility = ["//visibility:public"])
java_runtime(
    name = "jdk",
    srcs = glob(["**"]),
    java_home = ".",
)
toolchain(
    name = "runtime_toolchain",
    toolchain = ":jdk",
    toolchain_type = "@bazel_tools//tools/jdk:runtime_toolchain_type",
)
""",
)
JDKEOF
        echo "    Added local_jdk repository to WORKSPACE"
    else
        echo "    local_jdk already configured"
    fi
else
    echo "    Skipping (no Java 21 found - expected during vendoring on host)"
fi

# Fix 12: Add aarch64-linux CC toolchain for native ARM64 builds
# The vendored llvm_toolchain only defines x86_64 toolchains, so ARM64 CI fails
# with "Unable to find a CC toolchain" when --platforms=linux_arm64 is set
echo "  - Adding aarch64-linux CC toolchain to llvm_toolchain..."
LLVM_TOOLCHAIN_BUILD="ossm/vendor/llvm_toolchain/BUILD.bazel"
LLVM_TOOLCHAIN_BZL="ossm/vendor/llvm_toolchain/toolchains.bzl"

# Step A: Add aarch64-linux toolchain definition to BUILD.bazel
if [ -f "$LLVM_TOOLCHAIN_BUILD" ]; then
    if ! grep -q 'cc-toolchain-aarch64-linux' "$LLVM_TOOLCHAIN_BUILD"; then
        cat >> "$LLVM_TOOLCHAIN_BUILD" << 'AARCH64EOF'


# CC toolchain for cc-clang-aarch64-linux.
# Added by apply-build-fixes.sh for native ARM64 builds.

cc_toolchain_config(
    name = "local-aarch64-linux",
    exec_arch = "aarch64",
    exec_os = "linux",
    target_arch = "aarch64",
    target_os = "linux",
    target_system_name = "aarch64-unknown-linux-gnu",
    toolchain_path_prefix = "/usr/",
    tools_path_prefix = "/usr/bin/",
    wrapper_bin_prefix = "bin/",
    compiler_configuration = {
      "sysroot_path": "",
      "stdlib": "libc++",
      "cxx_standard": "c++20",
      "compile_flags": None,
      "conly_flags": [],
      "cxx_flags": None,
      "link_flags": None,
      "archive_flags": None,
      "link_libs": None,
      "fastbuild_compile_flags": None,
      "opt_compile_flags": None,
      "opt_link_flags": None,
      "dbg_compile_flags": None,
      "coverage_compile_flags": None,
      "coverage_link_flags": None,
      "unfiltered_compile_flags": None,
      "extra_compile_flags": None,
      "extra_cxx_flags": None,
      "extra_link_flags": None,
      "extra_archive_flags": None,
      "extra_link_libs": None,
      "extra_opt_compile_flags": None,
      "extra_opt_link_flags": None,
      "extra_dbg_compile_flags": None,
      "extra_coverage_compile_flags": None,
      "extra_coverage_link_flags": None,
      "extra_unfiltered_compile_flags": None,
    },
    extra_known_features = [],
    extra_enabled_features = [],
    cxx_builtin_include_directories = ["/usr/include/c++/v1", "/usr/lib/clang/21/include", "/usr/include/aarch64-unknown-linux-gnu/c++/v1", "/usr/lib64/clang/21.1.8/include", "/usr/lib64/clang/21/include", "/usr/include", "/usr/local/include"],
    major_llvm_version = 21,
)

toolchain(
    name = "cc-toolchain-aarch64-linux",
    exec_compatible_with = [
        "@platforms//cpu:aarch64",
        "@platforms//os:linux",
    ],
    target_compatible_with = [
        "@platforms//cpu:aarch64",
        "@platforms//os:linux",
    ],
    target_settings = None,
    toolchain = ":cc-clang-aarch64-linux",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

filegroup(
    name = "sysroot-components-aarch64-linux",
    srcs = [],
)

filegroup(
    name = "compiler-components-aarch64-linux",
    srcs = [
        ":sysroot-components-aarch64-linux",
    ],
)

filegroup(
    name = "linker-components-aarch64-linux",
    srcs = [
        ":sysroot-components-aarch64-linux",
    ],
)

filegroup(
    name = "all-components-aarch64-linux",
    srcs = [
        ":compiler-components-aarch64-linux",
        ":linker-components-aarch64-linux",
    ],
)

filegroup(name = "all-files-aarch64-linux", srcs = [":all-components-aarch64-linux", ":internal-use-tools-legacy"])
filegroup(name = "archiver-files-aarch64-linux", srcs = [":internal-use-tools-legacy"])
filegroup(name = "assembler-files-aarch64-linux", srcs = [":internal-use-tools-legacy"])
filegroup(name = "compiler-files-aarch64-linux", srcs = [":compiler-components-aarch64-linux", ":internal-use-tools-legacy"])
filegroup(name = "dwp-files-aarch64-linux", srcs = [":internal-use-tools-legacy"])
filegroup(name = "linker-files-aarch64-linux", srcs = [":linker-components-aarch64-linux", ":internal-use-tools-legacy"])
filegroup(name = "objcopy-files-aarch64-linux", srcs = [":internal-use-tools-legacy"])
filegroup(name = "strip-files-aarch64-linux", srcs = [":internal-use-tools-legacy"])

cc_toolchain(
    name = "cc-clang-aarch64-linux",
    all_files = "all-files-aarch64-linux",
    ar_files = "archiver-files-aarch64-linux",
    as_files = "assembler-files-aarch64-linux",
    compiler_files = "compiler-files-aarch64-linux",
    dwp_files = "dwp-files-aarch64-linux",
    linker_files = "linker-files-aarch64-linux",
    objcopy_files = "objcopy-files-aarch64-linux",
    strip_files = "strip-files-aarch64-linux",
    toolchain_config = "local-aarch64-linux",
    supports_header_parsing = True,
)
AARCH64EOF
        echo "    Added aarch64-linux CC toolchain to BUILD.bazel"
    else
        echo "    aarch64-linux CC toolchain already exists"
    fi
else
    echo "    Warning: llvm_toolchain/BUILD.bazel not found"
fi

# Step B: Register aarch64-linux toolchain in toolchains.bzl
if [ -f "$LLVM_TOOLCHAIN_BZL" ]; then
    if ! grep -q 'cc-toolchain-aarch64-linux' "$LLVM_TOOLCHAIN_BZL"; then
        sed -i 's|"@llvm_toolchain//:cc-toolchain-x86_64-none"|"@llvm_toolchain//:cc-toolchain-x86_64-none",\n        "@llvm_toolchain//:cc-toolchain-aarch64-linux"|' "$LLVM_TOOLCHAIN_BZL"
        echo "    Registered aarch64-linux toolchain in toolchains.bzl"
    else
        echo "    aarch64-linux toolchain already registered"
    fi
else
    echo "    Warning: llvm_toolchain/toolchains.bzl not found"
fi

echo ""
echo "Build fixes applied successfully!"
echo "You can now run: ./ossm/ci/pre-submit.sh"
