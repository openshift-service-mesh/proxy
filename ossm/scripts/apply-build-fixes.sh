#!/bin/bash
# Apply necessary fixes to vendored dependencies for Fedora 43 build compatibility
# Run this script after ossm/vendor is regenerated
#
# Note: LLVM toolchain CONFIGURATION (BUILD.bazel, cc_toolchain_config.bzl, toolchains.bzl)
# is vendored in ossm/vendor/llvm_toolchain/, but LLVM BINARIES are not. Instead:
# - Setting BAZEL_LLVM_PATH=/usr in update-deps.sh tells toolchains_llvm to use system LLVM
# - llvm.BUILD wraps system LLVM installation at /usr (similar to openssl.BUILD)
# - ossm/vendor/llvm_toolchain/bin/ contains symlinks to system tools (not binaries)

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

# Fix 13: Update Envoy's BoringSSL compat prefixer to use LLVM 21 instead of 18.1
echo "  - Updating prefixer BUILD to use LLVM 21..."
PREFIXER_BUILD="ossm/vendor/envoy/compat/openssl/prefixer/BUILD"
if [ -f "$PREFIXER_BUILD" ]; then
    if grep -q 'lib/libclang-cpp.so.18.1' "$PREFIXER_BUILD"; then
        sed -i 's|lib/libclang-cpp\.so\.18\.1|lib/libclang-cpp.so.21.1|g' "$PREFIXER_BUILD"
        echo "    Updated libclang-cpp version from 18.1 to 21.1"
    else
        echo "    libclang-cpp version already updated or not found"
    fi
else
    echo "    Warning: prefixer/BUILD not found (will be created during vendoring)"
fi

# Fix 14: Add LLVM library to prefixer deps for linking
echo "  - Adding LLVM library to prefixer deps..."
PREFIXER_BUILD="ossm/vendor/envoy/compat/openssl/prefixer/BUILD"
if [ -f "$PREFIXER_BUILD" ]; then
    if ! grep -q '"@llvm_toolchain_llvm//:llvm"' "$PREFIXER_BUILD"; then
        # Add LLVM to the deps list (after :llvm_headers)
        sed -i 's/deps = \[":llvm_headers"\]/deps = [":llvm_headers", "@llvm_toolchain_llvm\/\/:llvm"]/' "$PREFIXER_BUILD"
        echo "    Added @llvm_toolchain_llvm//:llvm to prefixer deps"
    else
        echo "    LLVM library already in prefixer deps"
    fi
else
    echo "    Warning: prefixer/BUILD not found (will be created during vendoring)"
fi

# Fix 15: Remove engine.h and engineerr.h from compat/openssl BUILD outs
# ENGINE API is deprecated in OpenSSL 3.x and these headers are skipped by prefixer
echo "  - Removing deprecated ENGINE headers from compat/openssl BUILD outputs..."
COMPAT_OPENSSL_BUILD="ossm/vendor/envoy/compat/openssl/BUILD"
if [ -f "$COMPAT_OPENSSL_BUILD" ]; then
    if grep -q 'include/ossl/openssl/engine.h' "$COMPAT_OPENSSL_BUILD"; then
        sed -i '/include\/ossl\/openssl\/engine\.h/d' "$COMPAT_OPENSSL_BUILD"
        sed -i '/include\/ossl\/openssl\/engineerr\.h/d' "$COMPAT_OPENSSL_BUILD"
        echo "    Removed engine.h and engineerr.h from outs list"
    else
        echo "    ENGINE headers already removed from outs"
    fi
else
    echo "    Warning: compat/openssl/BUILD not found"
fi

# Fix 16: Add architecture-specific configuration headers to BUILD and create symlinks
# The prefixer generates configuration.h which tries to #include architecture-specific headers.
# We need to ensure all declared outputs exist by copying configuration.h to the native arch
# and symlinking the others.
echo "  - Configuring architecture-specific OpenSSL headers in compat/openssl BUILD..."
COMPAT_OPENSSL_BUILD="ossm/vendor/envoy/compat/openssl/BUILD"

if [ -f "$COMPAT_OPENSSL_BUILD" ]; then
    # First, ensure architecture-specific headers are in the outs list
    if ! grep -q 'include/ossl/openssl/configuration-x86_64.h' "$COMPAT_OPENSSL_BUILD"; then
        # Find the configuration.h line and add arch-specific headers after it
        sed -i '/include\/ossl\/openssl\/configuration\.h/a\        "include/ossl/openssl/configuration-x86_64.h",\n        "include/ossl/openssl/configuration-aarch64.h",\n        "include/ossl/openssl/configuration-s390x.h",\n        "include/ossl/openssl/configuration-ppc64le.h",' "$COMPAT_OPENSSL_BUILD"
        echo "    Added architecture-specific configuration headers to outs"
    else
        echo "    Architecture-specific configuration headers already in outs"
    fi

    # Patch the genrule cmd to create architecture-specific headers after prefixer runs
    # We detect the native architecture and copy configuration.h to that arch-specific name,
    # then symlink the others to it (all outputs must exist per Bazel requirements)

    # First, clean up any previously inserted script that might be in the wrong location
    if grep -q 'NATIVE_ARCH=' "$COMPAT_OPENSSL_BUILD"; then
        # Remove lines from "# Create architecture-specific" to "done" after the closing """
        sed -i '/""",$/{n; /^$/,/^        done$/ {/# Create architecture-specific/,/done/d}}' "$COMPAT_OPENSSL_BUILD"
    fi

    if ! grep -q 'NATIVE_ARCH=' "$COMPAT_OPENSSL_BUILD"; then
        # Insert script before the closing """ in prefixed_ossl_source genrule
        # We use awk to find the line and sed to insert
        LINE_NUM=$(awk '/name = "prefixed_ossl_source"/,/""",$/ {if (/""",$/) {print NR; exit}}' "$COMPAT_OPENSSL_BUILD")

        if [ -n "$LINE_NUM" ]; then
            # Create temp file with the script to insert
            cat > /tmp/arch_script.txt << 'ARCHEOF'

        # Create architecture-specific configuration headers (added by apply-build-fixes.sh)
        # OpenSSL packaging varies by architecture:
        # - x86_64: Ships configuration.h (dispatcher) + configuration-x86_64.h (actual config)
        # - aarch64/s390x/ppc64le: Ships only configuration.h (actual config, no dispatcher)
        # The prefixer processes whatever exists and creates ossl/openssl/configuration*.h
        # We need to ensure all 4 arch-specific headers exist (required by BUILD outputs)
        NATIVE_ARCH=$$(uname -m)

        # Check if the native arch-specific header was created by prefixer
        case "$$NATIVE_ARCH" in
            x86_64) NATIVE_CONFIG="configuration-x86_64.h" ;;
            aarch64) NATIVE_CONFIG="configuration-aarch64.h" ;;
            s390x) NATIVE_CONFIG="configuration-s390x.h" ;;
            ppc64le) NATIVE_CONFIG="configuration-ppc64le.h" ;;
            *) echo "Unknown architecture: $$NATIVE_ARCH"; exit 1 ;;
        esac

        # If native arch-specific header doesn't exist, copy from configuration.h
        if [ ! -f "$(RULEDIR)/include/ossl/openssl/$$NATIVE_CONFIG" ]; then
            cp $(RULEDIR)/include/ossl/openssl/configuration.h $(RULEDIR)/include/ossl/openssl/$$NATIVE_CONFIG
        fi

        # Symlink all other architectures to the native one
        for ARCH_CONFIG in configuration-x86_64.h configuration-aarch64.h configuration-s390x.h configuration-ppc64le.h; do
            if [ "$$ARCH_CONFIG" != "$$NATIVE_CONFIG" ]; then
                ln -sf $$NATIVE_CONFIG $(RULEDIR)/include/ossl/openssl/$$ARCH_CONFIG
            fi
        done
ARCHEOF

            # Insert before the line with """ (using i\ to insert BEFORE, not r to insert AFTER)
            # First decrement LINE_NUM to insert before it
            LINE_NUM=$((LINE_NUM - 1))
            sed -i "${LINE_NUM}r /tmp/arch_script.txt" "$COMPAT_OPENSSL_BUILD"
            rm /tmp/arch_script.txt
            echo "    Patched genrule to create architecture-specific headers"
        else
            echo "    Warning: Could not find closing \"\"\" in prefixed_ossl_source genrule"
        fi
    else
        echo "    Genrule already patched for architecture-specific headers"
    fi
else
    echo "    Warning: compat/openssl/BUILD not found"
fi

echo ""
echo "Build fixes applied successfully!"
echo "You can now run: ./ossm/ci/pre-submit.sh"
