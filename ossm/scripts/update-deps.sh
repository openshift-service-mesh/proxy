#!/bin/bash
# Copyright Red Hat, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

export CC=clang CXX=clang++ ENVOY_OPENSSL=1

# Use system LLVM instead of downloading 9.6GB toolchain
# This tells envoy's toolchains_llvm to generate @llvm_toolchain with absolute
# paths to /usr/bin/clang, /usr/bin/llvm-ar, etc. — no symlinks or wrapper repos needed
export BAZEL_LLVM_PATH=/usr
export BAZEL_USE_HOST_SYSROOT=True

function init(){
  ROOT_DIR="$(pwd)"

  OUTPUT_BASE="$(mktemp -d)"
  VENDOR_DIR="${ROOT_DIR}/ossm/vendor"
  BAZELRC="${ROOT_DIR}/ossm/bazelrc-vendor"

  rm -rf "${OUTPUT_BASE}" &&  mkdir -p "${OUTPUT_BASE}"
  rm -rf "${VENDOR_DIR}" &&  mkdir -p "${VENDOR_DIR}"
  : > "${BAZELRC}"

  # Remove symlinks to previous builds to avoid issues
  rm -f bazel-*


  IGNORE_LIST=(
        "bazel_tools"
        "envoy_api"
        "envoy_build_config"
        "local_config"
        "local_jdk"
        "bazel_gazelle_go"
        "openssl"
        "llvm_toolchain_llvm"
        "go_sdk"
        "host_platform"
        "remotejdk"
        "rust"
        "nodejs"
        "rules_foreign_cc_framework_toolchain_freebsd_commands"
        "rules_foreign_cc_framework_toolchain_macos_commands"
        "rules_foreign_cc_framework_toolchain_windows_commands"
        "emscripten"
        "python3_12_host"
        "python3_12_x86_64"
        "python3_12_ppc"
        "python3_12_s390x"
        "python3_12_aarch64"
  )
}

function error() {
  echo "$@"
  exit 1
}

function validate() {
  if [ ! -f "WORKSPACE" ]; then
    error "Must run in the envoy/proxy dir"
  fi
}

function contains () {
  local e match="$1"
  shift
  for e; do [[ "$match" == "$e"* ]] && return 0; done
  return 1
}

function copy_files() {
  local cp_flags
  for f in "${OUTPUT_BASE}"/external/*; do
    if [ -d "${f}" ]; then
      repo_name=$(basename "${f}")
      if contains "${repo_name}" "${IGNORE_LIST[@]}" ; then
        continue
      fi

      cp_flags="-rL"
      if [ "${repo_name}" == "emscripten_toolchain" ] || [ "${repo_name}" == "antlr4-cpp-runtime" ] || [ "${repo_name}" == "envoy_toolshed" ] || [[ "${repo_name}" == *"luajit2"* ]] || [ "${repo_name}" == "llvm_toolchain" ]; then
        cp_flags="-r"
      fi
      cp "${cp_flags}" "${f}" "${VENDOR_DIR}" || echo "Copy of ${f} failed. Ignoring..."
      echo "build --override_repository=${repo_name}=%workspace%/ossm/vendor/${repo_name}" >> "${BAZELRC}"
    fi
  done


  chmod -R +w "${VENDOR_DIR}"
  find "${VENDOR_DIR}" -name .git -type d -print0 | xargs -0 -r rm -rf
  find "${VENDOR_DIR}" -name .gitignore -type f -delete
  find "${VENDOR_DIR}" -name __pycache__ -type d -print0 | xargs -0 -r rm -rf
  find "${VENDOR_DIR}" -name '*.pyc' -delete
}

function patch_java_tools() {
  # Patch remote_java_tools to add missing prebuilt_one_version target
  # Newer rules_java expects this but older vendored java_tools don't provide it
  for java_tools_dir in "${OUTPUT_BASE}"/external/remote_java_tools*; do
    if [ -d "${java_tools_dir}" ]; then
      local java_tools_build="${java_tools_dir}/BUILD"
      if [ -f "${java_tools_build}" ] && ! grep -q "prebuilt_one_version" "${java_tools_build}"; then
        echo "Patching $(basename ${java_tools_dir}) to add missing prebuilt_one_version target..."
        # Make file writable (Bazel output base files are read-only)
        chmod +w "${java_tools_build}"
        cat >> "${java_tools_build}" << 'EOF'

# Added by update-deps.sh to satisfy rules_java toolchain requirements
filegroup(
    name = "prebuilt_one_version",
    srcs = [],
)
EOF
      fi
    fi
  done
}

function patch_openssl_compat() {
  # Patch Envoy's compat/openssl/BUILD to fix OPENSSL_INCLUDE_DIR extraction
  # The upstream BUILD uses $(location) which fails when @openssl//:include
  # expands to multiple files. We need $(locations) and directory extraction.
  local envoy_compat_build="${OUTPUT_BASE}/external/envoy/compat/openssl/BUILD"

  if [ ! -f "${envoy_compat_build}" ]; then
    echo "WARNING: envoy/compat/openssl/BUILD not found at ${envoy_compat_build}"
    return
  fi

  echo "Patching envoy/compat/openssl/BUILD..."
  chmod +w "${envoy_compat_build}"

  # Remove @llvm_toolchain_llvm//:include from srcs (not needed)
  if grep -q '@llvm_toolchain_llvm//:include' "${envoy_compat_build}"; then
    echo "  - Removing unused @llvm_toolchain_llvm//:include"
    sed -i '/@llvm_toolchain_llvm\/\/:include/d' "${envoy_compat_build}"
  fi

  # Fix OPENSSL_INCLUDE_DIR extraction to handle multiple files
  # Use awk for more reliable multi-line replacement
  if grep -q 'OPENSSL_INCLUDE_DIR=$(location' "${envoy_compat_build}"; then
    echo "  - Fixing OPENSSL_INCLUDE_DIR extraction (changing location to locations)"
    awk '
    /OPENSSL_INCLUDE_DIR=\$\(location .*openssl.*:include\)/ {
        print "        # Extract the include directory from the list of OpenSSL headers"
        print "        # $(locations) returns space-separated list like \"/usr/include/openssl/ssl.h ...\""
        print "        # We take the first file and go up two directories: ssl.h -> openssl/ -> include/"
        print "        FIRST_HEADER=($(locations @@openssl//:include))"
        print "        OPENSSL_INCLUDE_DIR=$$(dirname $$(dirname $${FIRST_HEADER[0]}))"
        next
    }
    { print }
    ' "${envoy_compat_build}" > "${envoy_compat_build}.tmp"
    mv "${envoy_compat_build}.tmp" "${envoy_compat_build}"
    echo "  - Patch applied successfully"
  else
    echo "  - Pattern not found or already patched"
  fi
}

function run_bazel() {
  # Workaround to force fetch of rules_license
  bazel --output_base="${OUTPUT_BASE}" fetch @remote_java_tools//java_tools/zlib:zlib || true

  # Patch Java tools after initial fetch but before full build analysis
  patch_java_tools

  # Workaround to force fetch of protoc for arm
  bazel --output_base="${OUTPUT_BASE}" fetch @com_google_protobuf_protoc_linux_aarch_64//:protoc

  bazel --output_base="${OUTPUT_BASE}" fetch @gperftools//:all

  # Fetch all the rest and check everything using "build --nobuild "option
  # Note: The envoy repository is automatically patched via patches = [...] in WORKSPACE
  for config in x86_64 aarch64 s390x ppc; do
    bazel --output_base="${OUTPUT_BASE}" build --nobuild --keep_going --config="${config}" //...
  done
}

function patch_python() {
  local dir repo_name

  for arch in x86_64 s390x ppc64le aarch64; do
    repo_name="python3_12_${arch}-unknown-linux-gnu"
    dir="${VENDOR_DIR}/${repo_name}"
    /bin/rm -rf "${dir}"
    mkdir -p "${dir}"
    cp "${ROOT_DIR}/ossm/scripts/BUILD.bazel.python" "${dir}/BUILD.bazel"

    echo "build --override_repository=${repo_name}=%workspace%/ossm/vendor/${repo_name}" >> "${BAZELRC}"
    echo "workspace(name = \"${repo_name}\")" > "${dir}/WORKSPACE"
  done
}

function main() {
  validate
  init
  run_bazel
  copy_files
  patch_python

  echo
  echo "Dependencies vendored successfully. Applying build fixes..."
  echo

  # Apply build fixes automatically
  "${ROOT_DIR}/ossm/scripts/apply-build-fixes.sh"

  echo
  echo "Done. Inspect the result with git status"
  echo
}

main
