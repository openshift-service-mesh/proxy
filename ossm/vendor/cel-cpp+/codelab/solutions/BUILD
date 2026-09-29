# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

cc_library(
    name = "exercise1",
    srcs = ["exercise1.cc"],
    hdrs = ["//codelab:exercise1.h"],
    deps = [
        "//checker:validation_result",
        "//common:ast",
        "//common:minimal_descriptor_pool",
        "//common:value",
        "//compiler",
        "//compiler:compiler_factory",
        "//compiler:standard_library",
        "//internal:status_macros",
        "//runtime",
        "//runtime:activation",
        "//runtime:runtime_builder",
        "//runtime:runtime_options",
        "//runtime:standard_runtime_builder_factory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "exercise1_test",
    srcs = ["//codelab:exercise1_test.cc"],
    deps = [
        ":exercise1",
        "//internal:testing",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "exercise2",
    srcs = ["exercise2.cc"],
    hdrs = ["//codelab:exercise2.h"],
    deps = [
        "//checker:type_checker_builder",
        "//checker:validation_result",
        "//common:ast",
        "//common:decl",
        "//common:type",
        "//common:value",
        "//compiler",
        "//compiler:compiler_factory",
        "//compiler:standard_library",
        "//internal:status_macros",
        "//runtime",
        "//runtime:activation",
        "//runtime:bind_proto_to_activation",
        "//runtime:runtime_builder",
        "//runtime:runtime_options",
        "//runtime:standard_runtime_builder_factory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googleapis//google/rpc/context:attribute_context_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "exercise2_test",
    srcs = ["//codelab:exercise2_test.cc"],
    deps = [
        ":exercise2",
        "//internal:testing",
        "@com_google_absl//absl/status",
        "@com_google_googleapis//google/rpc/context:attribute_context_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "exercise3_test",
    srcs = ["exercise3_test.cc"],
    deps = [
        ":exercise2",
        "//internal:testing",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googleapis//google/rpc/context:attribute_context_cc_proto",
    ],
)

cc_library(
    name = "exercise4",
    srcs = ["exercise4.cc"],
    hdrs = ["//codelab:exercise4.h"],
    deps = [
        "//checker:type_checker_builder",
        "//checker:validation_result",
        "//common:ast",
        "//common:decl",
        "//common:type",
        "//common:value",
        "//compiler",
        "//compiler:compiler_factory",
        "//compiler:standard_library",
        "//internal:status_macros",
        "//runtime",
        "//runtime:activation",
        "//runtime:bind_proto_to_activation",
        "//runtime:function_adapter",
        "//runtime:runtime_builder",
        "//runtime:runtime_options",
        "//runtime:standard_runtime_builder_factory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_googleapis//google/rpc/context:attribute_context_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "exercise4_test",
    srcs = ["//codelab:exercise4_test.cc"],
    deps = [
        ":exercise4",
        "//internal:testing",
        "@com_google_googleapis//google/rpc/context:attribute_context_cc_proto",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:struct_cc_proto",
    ],
)

cc_library(
    name = "exercise10",
    srcs = ["exercise10.cc"],
    hdrs = ["//codelab:exercise10.h"],
    deps = [
        "//checker:validation_result",
        "//codelab:network_functions",
        "//common:ast",
        "//common:decl",
        "//common:minimal_descriptor_pool",
        "//common:type",
        "//common:value",
        "//compiler",
        "//compiler:compiler_factory",
        "//compiler:standard_library",
        "//internal:status_macros",
        "//runtime",
        "//runtime:activation",
        "//runtime:runtime_builder",
        "//runtime:runtime_options",
        "//runtime:standard_runtime_builder_factory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "exercise10_test",
    srcs = ["//codelab:exercise10_test.cc"],
    deps = [
        ":exercise10",
        "//internal:testing",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_protobuf//:protobuf",
    ],
)
