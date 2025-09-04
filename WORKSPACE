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
# Commit date: 09/04/25
ENVOY_SHA = "93466adc53567315e3114d6d1774c56f8066d24e"

ENVOY_SHA256 = "703aa4a59c2771681ab2b3ef878c2374e3a94b160b40122c03cd8d2c6debf7bd"

ENVOY_ORG = "envoyproxy"

ENVOY_REPO = "envoy"

OPENSSL_ENVOY_SHA = "14113b3b7593aabd76e7ca30fc5a5d1635900a13"
OPENSSL_ENVOY_SHA256 = "23a40185710dedfbd19439c7638d6e7b4139b0b83989d74d8ec423e6ad4920b3"
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
