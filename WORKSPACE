# Copyright 2016 Google Inc. All Rights Reserved.
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
################################################################################
#
workspace(name = "io_istio_proxy")

# http_archive is not a native function since bazel 0.19
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# 1. Determine SHA256 `wget https://github.com/envoyproxy/envoy/archive/$COMMIT.tar.gz && sha256sum $COMMIT.tar.gz`
# 2. Update .bazelversion, envoy.bazelrc and .bazelrc if needed.
#
# Commit date: 2026-05-29
ENVOY_SHA = "b05a001c9db8612ca8de7c4608ee6fb23059895c"

ENVOY_SHA256 = "22a0bff8dba1c9085d18e3d1e85428e4924bb2d1783ca77fc10863d19904d741"

ENVOY_ORG = "envoyproxy"

ENVOY_REPO = "envoy"

# Use OpenSSL from the system rather than vendoring it
# IMPORTANT: Must be defined BEFORE @envoy because the Envoy patch references @@openssl
new_local_repository(
    name = "openssl",
    path = "/usr/",
    build_file = "//:openssl.BUILD",
)

# To override with local envoy, just pass `--override_repository=envoy=/PATH/TO/ENVOY` to Bazel or
# persist the option in `user.bazelrc`.
http_archive(
    name = "envoy",
    sha256 = ENVOY_SHA256,
    strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
    url = "https://github.com/" + ENVOY_ORG + "/" + ENVOY_REPO + "/archive/" + ENVOY_SHA + ".tar.gz",
    patches = [
        "//ossm/patches:envoy-compat-openssl.patch",
    ],
    patch_args = ["-p1"],
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

local_repository(
    name = "envoy_build_config",
    # Relative paths are also supported.
    path = "bazel/extension_config",
)

# Use system LLVM from the host (for BoringSSL compat layer prefixer tool)
new_local_repository(
    name = "llvm_toolchain_llvm",
    path = "/usr/",
    build_file = "//:llvm.BUILD",
)

# Use system JDK for Java runtime (needed by ANTLR4 and other Java tools)
new_local_repository(
    name = "local_jdk",
    path = "/usr/lib/jvm/java-21-openjdk",
    build_file_content = """
java_runtime(
    name = "jdk",
    java_home = "/usr/lib/jvm/java-21-openjdk",
    visibility = ["//visibility:public"],
)

# Main runtime toolchain
toolchain(
    name = "runtime_toolchain",
    exec_compatible_with = [],
    target_compatible_with = [],
    toolchain = ":jdk",
    toolchain_type = "@bazel_tools//tools/jdk:runtime_toolchain_type",
)

# Bootstrap runtime toolchain (same as main for system JDK)
toolchain(
    name = "bootstrap_runtime_toolchain",
    exec_compatible_with = [],
    target_compatible_with = [],
    toolchain = ":jdk",
    toolchain_type = "@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type",
)

# Aliases for compatibility with Bazel's expectations
alias(
    name = "runtime_toolchain_definition",
    actual = ":runtime_toolchain",
    visibility = ["//visibility:public"],
)

alias(
    name = "bootstrap_runtime_toolchain_definition",
    actual = ":bootstrap_runtime_toolchain",
    visibility = ["//visibility:public"],
)

# Additional standard targets that Bazel might expect
alias(
    name = "jre",
    actual = ":jdk",
    visibility = ["//visibility:public"],
)

alias(
    name = "java",
    actual = ":jdk",
    visibility = ["//visibility:public"],
)
""",
)

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:bazel_deps.bzl", "envoy_bazel_dependencies")

envoy_bazel_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra(
    glibc_version = "2.28",
    ignore_root_user_error = True,
)

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@base_pip3//:requirements.bzl", "install_deps")

install_deps()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

# Use host Go instead of downloading to enable offline builds
envoy_dependency_imports(go_version = "host")

load("@envoy//bazel:repo.bzl", "envoy_repo")

envoy_repo()

load("@envoy//bazel:toolchains.bzl", "envoy_toolchains")

envoy_toolchains()

load("@llvm_toolchain//:toolchains.bzl", "llvm_register_toolchains")

llvm_register_toolchains()

# Register system Java runtime toolchains (both regular and bootstrap)
register_toolchains(
    "@local_jdk//:runtime_toolchain",
    "@local_jdk//:bootstrap_runtime_toolchain",
)
