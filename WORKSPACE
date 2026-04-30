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

# Use OpenSSL from the system rather than vendoring it
new_local_repository(
    name = "openssl",
    path = "/usr/lib64/",
    build_file = "//:openssl.BUILD"
)

# Add luajit2 for s390x and ppc architecture support
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "com_github_luajit2_luajit2",
    build_file_content = """
filegroup(
    name = "all",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
""",
    sha256 = "1e2374ac75618862d8c81bd5fc496fa7428c278164ad375a3e6b746e8833c0d2",
    strip_prefix = "luajit2-dcc9c9ee67e1a5d3d636bd7745e95ddb4a1c70bc",
    urls = ["https://github.com/openresty/luajit2/archive/dcc9c9ee67e1a5d3d636bd7745e95ddb4a1c70bc.tar.gz"],
    patches = ["@envoy//bazel/foreign_cc:luajit.patch"],
    patch_args = ["-p1"],
)

# 1. Determine SHA256 `wget https://github.com/envoyproxy/envoy/archive/$COMMIT.tar.gz && sha256sum $COMMIT.tar.gz`
# 2. Update .bazelversion, envoy.bazelrc and .bazelrc if needed.
#
# Commit date: 2026-04-24
ENVOY_SHA = "fa21ad4b3e69db0b1fef628a18964e7d26af5b31"

ENVOY_SHA256 = "7772dcebb478b0d000c4b03a767c451d9fb629a0fc71ce7714ce0e423cc1a92f"

ENVOY_ORG = "envoyproxy"

ENVOY_REPO = "envoy"

boringssl = {                                                                
      "sha": ENVOY_SHA,                                                        
      "sha256": ENVOY_SHA256,                                                  
      "org": ENVOY_ORG,                                                        
      "repo": ENVOY_REPO,                                                      
      }                                                                            
                                                                          
openssl = {                                                                  
      "sha": ENVOY_SHA,                                                
      "sha256": ENVOY_SHA256,                                          
      "org": ENVOY_ORG,                                                
      "repo": ENVOY_REPO,                                              
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

load("@envoy//bazel:repo.bzl", "envoy_repo")

envoy_repo()

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

envoy_dependency_imports(go_version = "host")

load("@envoy//bazel:toolchains.bzl", "envoy_toolchains")

envoy_toolchains()

load("@envoy//bazel:dependency_imports_extra.bzl", "envoy_dependency_imports_extra")

envoy_dependency_imports_extra()
