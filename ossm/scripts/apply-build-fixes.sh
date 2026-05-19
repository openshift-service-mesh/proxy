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


# Fix 7: Configure WORKSPACE to use system LLVM (like OpenSSL)
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

# Fix 11: Create symlinks in llvm_toolchain/bin to system LLVM tools
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
    ln -sf /usr/bin/llvm-dwp-21 llvm-dwp || true
    ln -sf /usr/bin/llvm-profdata-21 llvm-profdata || true
    ln -sf /usr/bin/llvm-cov-21 llvm-cov || true
    ln -sf /usr/bin/llvm-objcopy-21 llvm-objcopy || true
    ln -sf /usr/bin/llvm-objdump-21 llvm-objdump || true

    cd "$ROOT_DIR"
    echo "    Created symlinks to system LLVM tools"
else
    echo "    Warning: llvm_toolchain/bin not found - may need to run update-deps.sh first"
fi

# Fix 8: Update llvm_toolchain to use Clang 21 paths
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

# Fix 9: Configure rules_foreign_cc to use preinstalled tools instead of bootstrapping
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

# Fix 10: Create llvm_toolchain_llvm directory for Go CGO
# Go's runtime/cgo looks for clang in toolchain_path_prefix which points to this vendored location
echo "  - Creating llvm_toolchain_llvm directory for Go CGO..."
LLVM_TOOLCHAIN_LLVM_BIN="ossm/vendor/llvm_toolchain_llvm/bin"
mkdir -p "$LLVM_TOOLCHAIN_LLVM_BIN"
cd "$LLVM_TOOLCHAIN_LLVM_BIN"
ln -sf /usr/bin/clang-21 clang || true
ln -sf /usr/bin/clang++-21 clang++ || true
cd "$ROOT_DIR"
echo "    Created llvm_toolchain_llvm directory with clang symlinks"

echo ""
echo "Build fixes applied successfully!"
echo "You can now run: ./ossm/ci/pre-submit.sh"
