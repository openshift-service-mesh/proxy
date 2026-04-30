# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Maistra Proxy** repository - a fork of [Istio Proxy](https://github.com/istio/proxy) maintained for OpenShift Service Mesh by Red Hat. Istio Proxy is a microservice proxy based on [Envoy](https://envoyproxy.io) with additional policy and telemetry extensions.

### Key Differences from Upstream Istio Proxy

- Uses **OpenSSL** instead of BoringSSL (controlled by `ENVOY_OPENSSL=1` environment variable)
- In newer versions (v1.38+), uses upstream Envoy with unified OpenSSL/BoringSSL codebase
- Supports **s390x and ppc64le** platforms in addition to x86_64 and aarch64
- **Vendored dependencies**: All dependencies are stored in `ossm/vendor/` for offline builds
- Custom patches in `ossm/patches/` applied to Envoy during build

## Build System

Built with **Bazel 7.7.1**. All build configurations are in `.bazelrc` and `envoy.bazelrc`.

### Common Build Commands

```bash
# Standard build (uses environment CC=clang CXX=clang++ ENVOY_OPENSSL=1)
bazel build --config=release --config=x86_64 //:envoy

# Build for specific architecture
bazel build --config=release --config=aarch64 //:envoy  # or s390x, ppc

# Run all C++ tests
bazel test --config=release --config=x86_64 --build_tests_only //...

# Run Go integration tests (requires ENVOY_PATH set)
export ENVOY_PATH=bazel-bin/envoy
go test -timeout=30m -p=1 -parallel=1 $(go list ./...)

# Full build and test (CI script)
./ossm/ci/pre-submit.sh
```

### Build Configuration

- **Architecture configs**: `--config=x86_64`, `--config=aarch64`, `--config=s390x`, `--config=ppc`
- **Build mode**: `--config=release` (also available: `asan`, `tsan` for sanitizer builds)
- **Environment**: Set `CC=clang CXX=clang++ ENVOY_OPENSSL=1` before building
- **Vendored deps**: Loaded via `ossm/bazelrc-vendor` (auto-included in `.bazelrc`)
- **Cache**: Set `BAZEL_DISK_CACHE` or `BAZEL_REMOTE_CACHE` environment variable for build caching

### Running Single Tests

```bash
# Run a specific C++ test
bazel test --config=release --config=x86_64 //test/path/to:test_target

# Run a specific Go test
go test -v ./test/envoye2e/... -run TestName
```

## Architecture and Code Structure

### Directory Layout

- **`source/extensions/`**: Istio-specific C++ extensions to Envoy
  - `source/extensions/common/`: Shared utilities (metadata_object, workload_discovery, etc.)
  - `source/extensions/filters/http/`: HTTP-level filters
  - `source/extensions/filters/network/`: Network-level filters
- **`extensions/`**: WASM extension binaries (e.g., `attributegen.wasm`)
- **`test/`**: Go-based integration tests using Envoy binary
- **`bazel/`**: Bazel build configuration
  - `bazel/repositories.bzl`: Defines how Envoy is loaded (BoringSSL vs OpenSSL)
  - `bazel/extension_config/`: Envoy extension build configuration
- **`ossm/`**: Maistra-specific files
  - `ossm/vendor/`: All vendored Bazel dependencies
  - `ossm/patches/`: Patches applied to Envoy and dependencies
  - `ossm/scripts/`: Dependency management and build scripts
  - `ossm/ci/`: CI build scripts

### Envoy Integration

The WORKSPACE file defines the Envoy dependency via `define_envoy_implementation()`:
- Envoy is fetched as an http_archive from GitHub (org/repo specified by `ENVOY_ORG` and `ENVOY_REPO`)
- SHA and SHA256 are defined in WORKSPACE (`ENVOY_SHA`, `ENVOY_SHA256`)
- When `ENVOY_OPENSSL=1`, certain BoringSSL-specific extensions are disabled (e.g., cryptomb, QAT key providers)
- Patches from `ossm/patches/` are applied during Envoy fetch (cmake fixes, Python3 genrule, LuaJIT2 support)
- In v1.38+, OpenSSL and BoringSSL share the same upstream Envoy codebase

### Extension System

Extensions are built using Envoy's extension framework:
- Extensions are registered in `bazel/extension_config/extensions_build_config.bzl`
- Most extensions are built-in (not WASM)
- BUILD files define C++ libraries that register with Envoy's extension registry

## Dependency Management

### Updating Envoy Version

In newer versions (v1.38+), Envoy with OpenSSL uses the same codebase as Envoy with BoringSSL. Update both Envoy and dependencies with:

```bash
UPDATE_BRANCH=release/v1.38 ./scripts/update_envoy.sh
```

This script:
1. Fetches the latest commit SHA from the specified branch
2. Updates `ENVOY_SHA` and `ENVOY_SHA256` in WORKSPACE
3. Updates `.bazelversion` and `envoy.bazelrc` from the Envoy repository
4. Uses `ENVOY_ORG` and `ENVOY_REPO` values from WORKSPACE (currently "envoyproxy" and "envoy")

### Vendoring Dependencies

After changing dependencies in WORKSPACE or Bazel files, re-vendor with:
```bash
./ossm/scripts/update-deps.sh
```

This script:
1. Fetches all Bazel external dependencies for all architectures
2. Copies them to `ossm/vendor/`
3. Updates `ossm/bazelrc-vendor` with `--override_repository` flags
4. Removes `.git` directories and other unnecessary files
5. Automatically applies build fixes via `apply-build-fixes.sh` (fixes V8, luajit, foreign_cc compiler settings)

**Important**: After vendoring, commit both `ossm/vendor/` and `ossm/bazelrc-vendor`.

## Development Workflow

### Using Docker Builder (Recommended)

The standard development environment uses a Docker container with all tools pre-installed:

```bash
docker run --rm -it \
  --entrypoint bash \
  -w /work \
  -v $PWD:/work \
  -u $(id -u):$(id -g) \
  -v $HOME/bazel-cache:/bazel-cache \
  -v $HOME/bazel-base:/bazel-base \
  quay.io/maistra-dev/maistra-builder:3.4

# Inside container:
./ossm/ci/pre-submit.sh
```

The mounted volumes provide:
- `/work` - repository code
- `/bazel-cache` - persistent Bazel disk cache (significantly speeds up rebuilds)
- `/bazel-base` - persistent Bazel output base

The builder container definition is maintained in `~/TEST-INFRA/test-infra/docker/maistra-builder_3.4.Dockerfile`. This Dockerfile contains all the tooling needed for building (Bazel, clang, Go, etc.).

### Local Development

If building locally without Docker:
1. Install Bazel 7.7.1
2. Install clang/LLVM toolchain
3. Set environment: `export CC=clang CXX=clang++ ENVOY_OPENSSL=1`
4. Follow Envoy build prerequisites from [Envoy documentation](https://github.com/envoyproxy/envoy/blob/main/bazel/README.md)

### Making Changes

When modifying code:
1. **C++ Extensions**: Edit files in `source/extensions/`, update BUILD files if needed
2. **Build Configuration**: Modify Bazel files in `bazel/` or root directory
3. **Patches**: Add `.patch` files to `ossm/patches/` and update `bazel/repositories.bzl`
4. **Tests**: Add C++ tests alongside code, or Go integration tests in `test/`

Always test on all supported architectures if changes affect architecture-specific code.

## Versioning and Branching

- Branch naming follows Maistra versions: `maistra-2.3`, `maistra-3.4`, etc.
- Maistra versions align with Istio versions (e.g., Maistra 2.3 → Istio 1.14 → Proxy 1.14)
- The `master` branch is the default upstream tracking branch
- Each Maistra version is rebased from the corresponding Istio Proxy release branch

## CI/CD

- **Pre-submit**: `ossm/ci/pre-submit.sh` runs on PRs (builds + all tests)
- **Post-submit**: Builds artifacts and uploads to cloud storage
- **GitHub Actions**: `.github/workflows/update-envoy.yaml` automates Envoy updates
- **Automation**: Changes in maistra/envoy trigger automatic vendoring PRs in this repo

## Common Flags and Variables

- **ENVOY_OPENSSL=1**: Required - enables OpenSSL build mode
- **CC=clang CXX=clang++**: Use Clang compiler
- **BAZEL_DISK_CACHE**: Path for Bazel disk cache (significantly speeds up rebuilds)
- **BAZEL_REMOTE_CACHE**: URL for remote Bazel cache
- **CI=1**: Enables CI-specific build flags (resource throttling)
