#!/bin/bash
# Apply necessary fixes to vendored dependencies for Fedora 43 build compatibility
# Run this script after ossm/vendor is regenerated

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
if grep -q 'export PATH=\$\$(dirname \$\$(realpath \$(PYTHON3))):\$\$PATH' "$V8_FILE"; then
    sed -i '/export PATH=\$\$(dirname \$\$(realpath \$(PYTHON3))):\$\$PATH/d' "$V8_FILE"
    echo "    V8 fixed"
else
    echo "    V8 already fixed"
fi

# Fix 6: Fix luajit configure command
echo "  - Fixing luajit configure command..."
ENVOY_BUILD="ossm/vendor/envoy/bazel/foreign_cc/BUILD"
if grep -q 'configure_command = "build.py"' "$ENVOY_BUILD"; then
    sed -i 's/configure_command = "build.py"/configure_command = "luajit_build.sh"/' "$ENVOY_BUILD"
    echo "    luajit configure command fixed"
else
    echo "    luajit already fixed"
fi

# Fix 7: Add system compiler overrides to Envoy foreign_cc CMake targets
echo "  - Adding system compiler overrides to Envoy foreign_cc BUILD..."

if grep -q '"CMAKE_C_COMPILER": "/usr/bin/clang"' "$ENVOY_BUILD"; then
    echo "    Already patched, skipping"
else
    echo "    Applying patches..."

    # Create a Python script to do the patching
    python3 << 'EOFPYTHON'
import re

BUILD_FILE = "ossm/vendor/envoy/bazel/foreign_cc/BUILD"

with open(BUILD_FILE, "r") as f:
    content = f.read()

# Compiler override block to insert
compiler_flags = '''        # Force use of system compiler and sysroot instead of vendored LLVM toolchain
        "CMAKE_C_COMPILER": "/usr/bin/clang",
        "CMAKE_CXX_COMPILER": "/usr/bin/clang++",
        "CMAKE_C_FLAGS": "--sysroot=/",
        "CMAKE_CXX_FLAGS": "--sysroot=/ -stdlib=libc++",
        "CMAKE_EXE_LINKER_FLAGS": "--sysroot=/ -fuse-ld=/usr/bin/ld.lld-21",
'''

# Define target patterns and their markers
# We match the closing brace of cache_entries and insert before it
targets = [
    # libsxg target
    (r'(name = "libsxg".*?cache_entries = \{[^}]+)(\n\s+\},)',
     r'\1\n' + compiler_flags + r'\2'),

    # event target
    (r'("_GNU_SOURCE": "on",)(\n\s+\},\n\s+exec_properties)',
     r'\1\n' + compiler_flags + r'\2'),

    # nghttp2 target
    (r'("CMAKE_CXX_COMPILER_FORCED": "on",)(\n\s+\},\n\s+cmake_files_dir)',
     r'\1\n' + compiler_flags + r'\2'),

    # wamr target
    (r'("WAMR_BUILD_LINUX_PERF": "0",)(\n\s+\},\n\s+exec_properties)',
     r'\1\n' + compiler_flags + r'\2'),

    # maxmind target
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


# Fix 8: Configure WORKSPACE to use system LLVM (like OpenSSL)
echo "  - Configuring WORKSPACE to use system LLVM..."
WORKSPACE_FILE="WORKSPACE"

# Check if llvm_toolchain_llvm local repository is already configured
if ! grep -q 'name = "llvm_toolchain_llvm"' "$WORKSPACE_FILE"; then
    # Find the line with openssl new_local_repository and add LLVM after it
    # Insert after the openssl repository definition
    sed -i '/^new_local_repository(/,/^)/ {
        /^)/ a\
\
# Use LLVM from the system, not the one bundled in Envoy \
# Avoids vendoring 9.6GB of LLVM toolchain\
new_local_repository(\
    name = "llvm_toolchain_llvm",\
    path = "/usr",  # Use /usr so bin/clang resolves to /usr/bin/clang\
    build_file = "//:llvm.BUILD",\
)
    }' "$WORKSPACE_FILE"
    echo "    Added llvm_toolchain_llvm local repository to WORKSPACE"
else
    echo "    llvm_toolchain_llvm already configured in WORKSPACE"
fi

# Fix 9: Create symlinks in llvm_toolchain/bin to system LLVM tools
# The vendored llvm_toolchain is just config/wrappers, but needs access to system binaries
echo "  - Creating symlinks to system LLVM tools in llvm_toolchain/bin..."
LLVM_TOOLCHAIN_BIN="ossm/vendor/llvm_toolchain/bin"

if [ -d "$LLVM_TOOLCHAIN_BIN" ]; then
    # Create symlinks to system LLVM tools (with -21 suffix from Fedora packages)
    cd "$LLVM_TOOLCHAIN_BIN"

    # Core compiler tools (required for CGO and general compilation)
    ln -sf /usr/bin/clang-21 clang || true
    ln -sf /usr/bin/clang++-21 clang++ || true

    # Tools that may or may not exist - create if available
    [ -f /usr/bin/clang-cpp-21 ] && ln -sf /usr/bin/clang-cpp-21 clang-cpp
    [ -f /usr/bin/clang-format-21 ] && ln -sf /usr/bin/clang-format-21 clang-format
    [ -f /usr/bin/clang-tidy-21 ] && ln -sf /usr/bin/clang-tidy-21 clang-tidy
    [ -f /usr/bin/clangd-21 ] && ln -sf /usr/bin/clangd-21 clangd

    # Required tools (should always exist from clang21-devel/llvm21-devel)
    ln -sf /usr/bin/llvm-ar-21 llvm-ar || true
    ln -sf /usr/bin/llvm-nm-21 llvm-nm || true
    ln -sf /usr/bin/llvm-strip-21 llvm-strip || true
    ln -sf /usr/bin/llvm-dwp-21 llvm-dwp || true
    ln -sf /usr/bin/llvm-profdata-21 llvm-profdata || true
    ln -sf /usr/bin/llvm-cov-21 llvm-cov || true
    ln -sf /usr/bin/llvm-objcopy-21 llvm-objcopy || true
    ln -sf /usr/bin/llvm-objdump-21 llvm-objdump || true

    # Linker (from lld21 package)
    ln -sf /usr/bin/ld.lld-21 ld.lld || true
    ln -sf /usr/bin/lld-21 lld || true

    cd "$ROOT_DIR"
    echo "    Created symlinks to system LLVM tools"
else
    echo "    Warning: llvm_toolchain/bin not found - may need to run update-deps.sh first"
fi

# Fix 9b: Make llvm_toolchain bin directory visibility public
# The vendored BUILD.bazel has package(default_visibility = ["//visibility:public"])
# But we need to ensure bin/** files are explicitly exported for external references
# NOTE: exports_files with glob doesn't create individual targets - must list files explicitly
echo "  - Checking llvm_toolchain bin exports..."
LLVM_TOOLCHAIN_BUILD="ossm/vendor/llvm_toolchain/BUILD.bazel"
if [ -f "$LLVM_TOOLCHAIN_BUILD" ]; then
    # Check if bin directory is already exported via exports_files
    if ! grep -q "# Added by apply-build-fixes.sh: Export bin directory" "$LLVM_TOOLCHAIN_BUILD"; then
        # Add exports_files with explicit file list at the beginning of the file (after package declaration)
        sed -i '/^package(default_visibility/a\
\
# Added by apply-build-fixes.sh: Export bin directory\
# Allows external packages to reference bin/** files\
# Must list files explicitly - glob does not create individual targets\
exports_files([\
    "bin/clang",\
    "bin/clang++",\
    "bin/clang-cpp",\
    "bin/clang-format",\
    "bin/clang-tidy",\
    "bin/clangd",\
    "bin/ld.lld",\
    "bin/llvm-ar",\
    "bin/llvm-cov",\
    "bin/llvm-dwp",\
    "bin/llvm-nm",\
    "bin/llvm-objcopy",\
    "bin/llvm-objdump",\
    "bin/llvm-profdata",\
    "bin/llvm-strip",\
    "bin/cc_wrapper.sh",\
])
' "$LLVM_TOOLCHAIN_BUILD"
        echo "    Added explicit exports_files for bin directory"
    else
        echo "    Bin directory already exported"
    fi
else
    echo "    Warning: llvm_toolchain/BUILD.bazel not found - may need to run update-deps.sh first"
fi


# Fix 10: Update llvm_toolchain to use Clang 21 paths
echo "  - Updating llvm_toolchain to use Clang 21 paths..."
LLVM_TOOLCHAIN_BUILD="ossm/vendor/llvm_toolchain/BUILD.bazel"
if [ -f "$LLVM_TOOLCHAIN_BUILD" ]; then
    # First, replace any old Clang 18 paths with Clang 21
    if grep -q 'lib/clang/18/include' "$LLVM_TOOLCHAIN_BUILD"; then
        sed -i 's|lib/clang/18/include|lib/clang/21/include|g' "$LLVM_TOOLCHAIN_BUILD"
        echo "    Updated Clang 18 paths to Clang 21"
    fi

    # Then, check if /usr/lib/clang/21/include is already added as absolute path
    if ! grep -q '"/usr/lib/clang/21/include", "/usr/include"' "$LLVM_TOOLCHAIN_BUILD"; then
        # Add /usr/lib/clang/21/include before /usr/include in all cxx_builtin_include_directories
        sed -i 's|"/usr/include", "/usr/local/include"|"/usr/lib/clang/21/include", "/usr/include", "/usr/local/include"|g' "$LLVM_TOOLCHAIN_BUILD"
        echo "    Added /usr/lib/clang/21/include to cxx_builtin_include_directories"
    else
        echo "    /usr/lib/clang/21/include already in cxx_builtin_include_directories"
    fi
else
    echo "    Warning: llvm_toolchain/BUILD.bazel not found - may need to run update-deps.sh first"
fi

# Fix 11: Configure rules_foreign_cc to use preinstalled tools instead of bootstrapping
# Bootstrapping GNU Make fails with custom compiler flags (-idirafter)
# Use system make (/usr/bin/make) which is already installed in the container
echo "  - Configuring rules_foreign_cc to use preinstalled tools..."
DEPENDENCY_IMPORTS="ossm/vendor/envoy/bazel/dependency_imports.bzl"
if [ -f "$DEPENDENCY_IMPORTS" ]; then
    if ! grep -q "register_built_tools = False" "$DEPENDENCY_IMPORTS"; then
        # Use perl for proper multiline replacement
        perl -i -pe 's/rules_foreign_cc_dependencies\(\)/rules_foreign_cc_dependencies(\n        register_built_tools = False,\n        register_preinstalled_tools = True,\n    )/g' "$DEPENDENCY_IMPORTS"
        echo "    Configured rules_foreign_cc to use preinstalled tools"
    else
        echo "    rules_foreign_cc already configured for preinstalled tools"
    fi
else
    echo "    Warning: dependency_imports.bzl not found"
fi

# Fix 12: Create llvm_toolchain_llvm directory for Go CGO
# Go's runtime/cgo looks for clang in toolchain_path_prefix which points to this vendored location
echo "  - Creating llvm_toolchain_llvm directory for Go CGO..."
LLVM_TOOLCHAIN_LLVM_BIN="ossm/vendor/llvm_toolchain_llvm/bin"
mkdir -p "$LLVM_TOOLCHAIN_LLVM_BIN"
cd "$LLVM_TOOLCHAIN_LLVM_BIN"
ln -sf /usr/bin/clang-21 clang || true
ln -sf /usr/bin/clang++-21 clang++ || true
cd "$ROOT_DIR"
echo "    Created llvm_toolchain_llvm directory with clang symlinks"

# Fix 13: Add missing prebuilt_one_version target to remote_java_tools
# Newer rules_java expects this target but older vendored java_tools don't provide it
echo "  - Adding missing prebuilt_one_version target to remote_java_tools..."
for java_tools_dir in ossm/vendor/remote_java_tools*; do
    if [ -d "$java_tools_dir" ]; then
        REMOTE_JAVA_TOOLS_BUILD="${java_tools_dir}/BUILD"
        if [ -f "$REMOTE_JAVA_TOOLS_BUILD" ]; then
            if ! grep -q "prebuilt_one_version" "$REMOTE_JAVA_TOOLS_BUILD"; then
                # Add the missing target as an empty filegroup (it's not actually used in our build)
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

# Fix 14: Conditionally register system JDK as Java runtime toolchain
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

# Fix 15: Add aarch64-linux CC toolchain for native ARM64 builds
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
    toolchain_path_prefix = "external/llvm_toolchain_llvm/",
    tools_path_prefix = "bin/",
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
    cxx_builtin_include_directories = ["%workspace%/external/llvm_toolchain_llvm/include/c++/v1", "%workspace%/external/llvm_toolchain_llvm/lib/clang/21/include", "%workspace%/external/llvm_toolchain_llvm/include/aarch64-unknown-linux-gnu/c++/v1", "/usr/lib/clang/21/include", "/usr/include", "/usr/local/include"],
    major_llvm_version = 18,
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
    name = "cxx_builtin_include_files-aarch64-linux",
    srcs = ["@llvm_toolchain_llvm//:include"],
)

filegroup(
    name = "compiler-components-aarch64-linux",
    srcs = [
        ":cxx_builtin_include_files-aarch64-linux",
        ":sysroot-components-aarch64-linux",
        "@llvm_toolchain_llvm//:extra_config_site",
        "@llvm_toolchain_llvm//:clang",
    ],
)

filegroup(
    name = "linker-components-aarch64-linux",
    srcs = [
        "@llvm_toolchain_llvm//:clang",
        "@llvm_toolchain_llvm//:ld",
        "@llvm_toolchain_llvm//:ar",
        "@llvm_toolchain_llvm//:lib_legacy",
        ":sysroot-components-aarch64-linux",
    ],
)

filegroup(
    name = "all-components-aarch64-linux",
    srcs = [
        "@llvm_toolchain_llvm//:bin",
        ":compiler-components-aarch64-linux",
        ":linker-components-aarch64-linux",
    ],
)

filegroup(name = "all-files-aarch64-linux", srcs = [":all-components-aarch64-linux", ":internal-use-tools-legacy"])
filegroup(name = "archiver-files-aarch64-linux", srcs = ["@llvm_toolchain_llvm//:ar", ":internal-use-tools-legacy"])
filegroup(name = "assembler-files-aarch64-linux", srcs = ["@llvm_toolchain_llvm//:as", ":internal-use-tools-legacy"])
filegroup(name = "compiler-files-aarch64-linux", srcs = [":compiler-components-aarch64-linux", ":internal-use-tools-legacy"])
filegroup(name = "dwp-files-aarch64-linux", srcs = ["@llvm_toolchain_llvm//:dwp", ":internal-use-tools-legacy"])
filegroup(name = "linker-files-aarch64-linux", srcs = [":linker-components-aarch64-linux", ":internal-use-tools-legacy"])
filegroup(name = "objcopy-files-aarch64-linux", srcs = ["@llvm_toolchain_llvm//:objcopy", ":internal-use-tools-legacy"])
filegroup(name = "strip-files-aarch64-linux", srcs = ["@llvm_toolchain_llvm//:strip", ":internal-use-tools-legacy"])

system_module_map(
    name = "module-aarch64-linux",
    cxx_builtin_include_files = ":cxx_builtin_include_files-aarch64-linux",
    cxx_builtin_include_directories = ["%workspace%/external/llvm_toolchain_llvm/include/c++/v1", "%workspace%/external/llvm_toolchain_llvm/lib/clang/21/include", "%workspace%/external/llvm_toolchain_llvm/include/aarch64-unknown-linux-gnu/c++/v1", "/usr/lib/clang/21/include", "/usr/include", "/usr/local/include"],
    sysroot_files = ":sysroot-components-aarch64-linux",
    sysroot_path = "",
)

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
    module_map = "module-aarch64-linux",
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
