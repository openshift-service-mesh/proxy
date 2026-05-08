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
        "CMAKE_EXE_LINKER_FLAGS": "--sysroot=/ -fuse-ld=/usr/bin/ld.lld-18",
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

echo ""
echo "Build fixes applied successfully!"
echo "You can now run: ./ossm/ci/pre-submit.sh"
