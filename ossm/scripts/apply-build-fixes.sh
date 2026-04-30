#!/bin/bash
# Apply necessary fixes to vendored dependencies for Fedora 43 build compatibility
# Run this script after ossm/vendor is regenerated

set -e

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

echo "Applying build fixes to vendored dependencies..."

# Fix 1: Remove PYTHON3 make variable from V8
echo "  - Fixing V8 PYTHON3 genrule..."
V8_FILE="ossm/vendor/v8/BUILD.bazel"
if grep -q 'export PATH=\$\$(dirname \$\$(realpath \$(PYTHON3))):\$\$PATH' "$V8_FILE"; then
    sed -i '/export PATH=\$\$(dirname \$\$(realpath \$(PYTHON3))):\$\$PATH/d' "$V8_FILE"
    echo "    V8 fixed"
else
    echo "    V8 already fixed"
fi

# Fix 2: Fix luajit configure command
echo "  - Fixing luajit configure command..."
ENVOY_BUILD="ossm/vendor/envoy/bazel/foreign_cc/BUILD"
if grep -q 'configure_command = "build.py"' "$ENVOY_BUILD"; then
    sed -i 's/configure_command = "build.py"/configure_command = "luajit_build.sh"/' "$ENVOY_BUILD"
    echo "    luajit configure command fixed"
else
    echo "    luajit already fixed"
fi

# Fix 3: Add system compiler overrides to Envoy foreign_cc CMake targets
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
