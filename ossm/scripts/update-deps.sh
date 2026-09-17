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
#
# Regenerate the vendored dependency snapshot under ossm/vendor so that the
# Envoy build works in an offline (air-gapped) environment.
#
# Unlike the previous WORKSPACE-era approach (which manually copied every
# external repo and generated --override_repository lines), this uses Bazel's
# native bzlmod vendor mode: `bazel vendor` fetches exactly the repos the build
# analyses into --vendor_dir. Host toolchains are excluded via
# ossm/vendor/VENDOR.bazel and regenerated from the host at build time.
#
# Run this from a machine with network access and the OSSM host toolchains
# (clang/LLVM at /usr, host JDK/Go). Commit the resulting ossm/vendor tree.

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "${ROOT_DIR}"

VENDOR_DIR="ossm/vendor"

# Target architectures to vendor for. Each pulls its arch-specific deps; running
# them in one snapshot lets any of these arches build offline from it.
ARCHES=(x86_64 aarch64 s390x ppc)

# The build target whose transitive deps we vendor.
TARGET="//:envoy"

# Repos referenced only by global `--@repo//:flag` options in Envoy's imported
# .bazelrc (e.g. `build --@librdkafka//:with_ssl=false`). Bazel instantiates
# these at option-parse time, but their targets are not in //:envoy's build
# closure, so `bazel vendor <target>` never captures them -- and then an offline
# build fails loading the option. Vendor them explicitly with `--repo`. Their
# sources are arch-independent, so a single pass covers all arches. Canonical
# repo names (with the trailing `+`) are what `--repo` expects.
EXTRA_REPOS=(
  "@@librdkafka+"
  "@@libsxg+"
)

# Execution-platform (host) prebuilt tools for cross-arch offline builds.
# protoc and java_tools ship as prebuilt binaries selected by the *execution*
# platform. This snapshot is vendored on an x86_64 host and --config=aarch64 is
# a no-op here (it only sets --define=DUMMY; it does not cross-compile), so the
# arch loop only ever exercises the x86_64 execution platform. The aarch64 host
# variants are therefore never fetched, and an offline build *on an aarch64
# host* fails fetching protoc/java_tools. Vendor them explicitly by their
# canonical repo names. (Bazel java_tools only ships x86_64 and aarch64 for
# linux; s390x/ppc host builds fall back to building java_tools from source, so
# only aarch64 needs to be captured here.)
CROSS_ARCH_HOST_TOOLS=(
  "@@protobuf++protoc+prebuilt_protoc.linux_aarch_64"
  "@@rules_java++toolchains+remote_java_tools_linux_aarch64"
)

echo ">> Wiping stale snapshot (keeping VENDOR.bazel)"
if [ -d "${VENDOR_DIR}" ]; then
  find "${VENDOR_DIR}" -mindepth 1 -maxdepth 1 \
    ! -name VENDOR.bazel -exec rm -rf {} +
fi
mkdir -p "${VENDOR_DIR}"

for arch in "${ARCHES[@]}"; do
  echo ">> Vendoring ${TARGET} for --config=${arch}"
  bazel vendor \
    --config="${arch}" \
    --vendor_dir="${VENDOR_DIR}" \
    "${TARGET}"
done

echo ">> Vendoring option-referenced and cross-arch host-tool repos"
bazel vendor \
  --vendor_dir="${VENDOR_DIR}" \
  "${EXTRA_REPOS[@]/#/--repo=}" \
  "${CROSS_ARCH_HOST_TOOLS[@]/#/--repo=}"

echo ">> Recovering files bazel vendor skipped due to repo .gitignore rules"
# `bazel vendor` does not copy files matched by a repo's own bundled .gitignore
# into --vendor_dir, yet some are real build inputs -- e.g. libevent's
# overlay-provided include/event2/event-config.h, which libevent's .gitignore
# lists because it is normally build-generated. Skipping them leaves the offline
# build with "missing input file". The complete, unfiltered repos live in
# Bazel's external cache, which the vendor dir exposes via the bazel-external
# symlink. Copy back only files present there but missing from the snapshot
# (rsync --ignore-existing overwrites nothing) -- exactly the set bazel skipped.
# Runs before pruning so any recovered test data is still dropped below. Only
# vendored repos (those with a marker) are touched; ignore()'d host-backed repos
# have no marker and are left alone.
CACHE_DIR="${VENDOR_DIR}/bazel-external"
if [ -d "${CACHE_DIR}" ]; then
  for marker in "${VENDOR_DIR}"/@*.marker; do
    [ -e "${marker}" ] || continue
    repo="$(basename "${marker}" .marker)"
    repo="${repo#@}"
    [ -d "${CACHE_DIR}/${repo}" ] && [ -d "${VENDOR_DIR}/${repo}" ] || continue
    rsync -a --ignore-existing "${CACHE_DIR}/${repo}/" "${VENDOR_DIR}/${repo}/"
  done
fi

echo ">> Pruning content the //:envoy build never compiles (tests/docs/fixtures)"
# Upstream test suites, fuzz corpora, docs, and dev-container assets are not
# build inputs for //:envoy, so dropping them shrinks the committed snapshot
# substantially (~0.5GB). Vendor mode validates a repo by its marker (the repo
# rule + attributes), not by file contents, so removing extracted files does not
# trigger a re-fetch. Whole *unused repos* (e.g. the gazelle Go caches) are
# excluded via ossm/vendor/VENDOR.bazel ignore() instead -- deleting a whole
# vendored repo dir here would just make Bazel try to re-fetch it.
PRUNE_PATHS=(
  "boringssl-source+/third_party/wycheproof_testvectors"
  "boringssl-source+/fuzz"
  "boringssl-source+/pki/testdata"
  "wasmtime+/tests"
  "grpc+/doc"
  "grpc+/test"
  "envoy+/test"
  "envoy+/docs"
  "envoy+/mobile"
  "envoy+/.devcontainer"
)
for p in "${PRUNE_PATHS[@]}"; do
  rm -rf "${VENDOR_DIR:?}/${p}"
done
# BoringSSL scatters test data under crypto/**/test (no BUILD files there).
find "${VENDOR_DIR}/boringssl-source+/crypto" -depth -type d -name test \
  -exec rm -rf {} + 2>/dev/null || true

echo ">> Stripping Python bytecode caches"
# rules_python symlinks __pycache__ dirs to a writable location; those absolute
# symlinks are build-time junk (bytecode is regenerated) and must not be
# committed. Drop them along with any stray .pyc files.
find "${VENDOR_DIR}" -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "${VENDOR_DIR}" -name '*.pyc' -delete 2>/dev/null || true

echo ">> Stripping nested .gitignore files so git commits the whole snapshot"
# Vendored source trees carry their upstream .gitignore files, and `git add`
# honors those nested rules -- silently dropping vendored build inputs that match
# them (this is the other half of the event-config.h problem above). The files
# have no meaning in a committed snapshot (Bazel validates vendored repos by
# their marker, not by a file listing), so remove them. find does not descend
# the bazel-external symlink, so the cache is left untouched.
find "${VENDOR_DIR}" -name .gitignore -delete 2>/dev/null || true

echo ">> Generating --override_repository entries for the Go deps"
# gazelle's go_deps repos hold pure Go module *source* (arch-independent), but
# their vendor markers transitively hash the host `go` binary (via the rebuilt
# fetch_repo tool). So a snapshot vendored on one arch is always "out-of-date"
# on another, and Bazel tries to re-fetch these repos -- which fails in an
# offline build. As in the WORKSPACE era, --override_repository sidesteps marker
# validation entirely: an overridden repo is used directly from its path, with
# no marker check and no fetch. We emit one override per go_deps repo into a
# bazelrc that ossm/bazelrc try-imports. The arch-specific Go repos (go_toolchains
# and the gazelle tool binaries) are deliberately NOT overridden -- they rebuild
# or regenerate from the host toolchain at build time, offline, on any arch.
OVERRIDES_FILE="${VENDOR_DIR}/go_deps_overrides.bazelrc"
{
  echo "# Generated by ossm/scripts/update-deps.sh -- do not edit by hand."
  echo "# See the same-named step in that script for the rationale."
  for d in "${VENDOR_DIR}"/gazelle++go_deps+*/; do
    [ -d "${d}" ] || continue
    repo="$(basename "${d}")"
    echo "common --override_repository=${repo}=%workspace%/${VENDOR_DIR}/${repo}"
  done
} > "${OVERRIDES_FILE}"

echo ">> Checking for absolute symlinks that escaped into the snapshot"
# Any remaining absolute symlink pointing outside the workspace means a
# host-backed repo was vendored instead of ignored; add it to VENDOR.bazel.
# bazel-external is a generated symlink into the output base (gitignored).
strays="$(find "${VENDOR_DIR}" -type l -lname '/*' \
  ! -path "${VENDOR_DIR}/bazel-external" 2>/dev/null || true)"
if [ -n "${strays}" ]; then
  echo "WARNING: host-path symlinks found in the vendor snapshot:" >&2
  echo "${strays}" >&2
  echo "Add the owning repos to ${VENDOR_DIR}/VENDOR.bazel via ignore()." >&2
fi

echo ">> Done. Review and commit ${VENDOR_DIR}."
