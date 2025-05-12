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

load("//bazel:repositories.bzl", "define_envoy_implementation")

# 1. Determine SHA256 `wget https://github.com/envoyproxy/envoy/archive/$COMMIT.tar.gz && sha256sum $COMMIT.tar.gz`
# 2. Update .bazelversion, envoy.bazelrc and .bazelrc if needed.
#
# Commit date: 2025-04-11
ENVOY_SHA = "dc84fe53b5293da9475f12baa173e6cdc0baf238"

ENVOY_SHA256 = "8b7f76708b3e9fc5aa83f90e211033f7a2054df725fc47cd4191e6dc21fe7771"

ENVOY_ORG = "envoyproxy"

ENVOY_REPO = "envoy"

OPENSSL_ENVOY_SHA = "10a053f09423bbc0674eef6b9ddaf9156300459b"
OPENSSL_ENVOY_SHA256 = "db743527f0b69fbe70fe7bbd023626ddaaa8784cac6e3ef5d294a9a247150571"
OPENSSL_ENVOY_ORG = "envoyproxy"
OPENSSL_ENVOY_REPO = "envoy-openssl"

boringssl = {
    "sha": ENVOY_SHA,
    "sha256": ENVOY_SHA256,
    "org": ENVOY_ORG,
    "repo": ENVOY_REPO,
}

openssl = {
    "sha": OPENSSL_ENVOY_SHA,
    "sha256": OPENSSL_ENVOY_SHA256,
    "org": OPENSSL_ENVOY_ORG,
    "repo": OPENSSL_ENVOY_REPO,
}

# To override with local envoy, just pass `--override_repository=envoy=/PATH/TO/ENVOY` to Bazel or
# persist the option in `user.bazelrc`.

define_envoy_implementation(name="pick_envoy", boringssl=boringssl, openssl=openssl)
load("@pick_envoy//:load_envoy.bzl", "load_envoy")
load_envoy()

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

local_repository(
    name = "envoy_build_config",
    # Relative paths are also supported.
    path = "bazel/extension_config",
)

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra(ignore_root_user_error = True)

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@base_pip3//:requirements.bzl", "install_deps")

install_deps()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()
