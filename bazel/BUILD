# Copyright 2020 Istio Authors. All Rights Reserved.
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

load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")

licenses(["notice"])  # Apache 2

# SSL library selection using label_flag
label_flag(
    name = "ssl",
    build_setting_default = "@boringssl//:ssl",
    visibility = ["//visibility:public"],
)

label_flag(
    name = "crypto",
    build_setting_default = "@boringssl//:crypto",
    visibility = ["//visibility:public"],
)

bool_flag(
    name = "fips",
    build_setting_default = False,
    visibility = ["//visibility:public"],
)

config_setting(
    name = "fips_build",
    flag_values = {":fips": "True"},
    visibility = ["//visibility:public"],
)

config_setting(
    name = "using_boringssl",
    flag_values = {":ssl": "@boringssl//:ssl"},
    visibility = ["//visibility:public"],
)

config_setting(
    name = "using_boringssl_fips",
    flag_values = {":ssl": "@boringssl_fips//:ssl"},
    visibility = ["//visibility:public"],
)

config_setting(
    name = "using_aws_lc",
    flag_values = {":ssl": "@aws_lc//:ssl"},
    visibility = ["//visibility:public"],
)

config_setting(
    name = "using_openssl",
    flag_values = {":ssl": "@openssl//:ssl"},
    visibility = ["//visibility:public"],
)
