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

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

exports_files(
    srcs = glob([
        "exercise*.h",
        "exercise*_test.cc",
    ]),
    visibility = ["//codelab/solutions:__pkg__"],
)

# Exclude tests from tap and glob runs since they start failing for the codelab.
# The solutions directory has test targets that are included to catch breaking changes.
EXERCISE_TEST_TAGS = [
    "manual",
    "notap",
    "norapid",
]

cc_library(
    name = "exercise1",
    srcs = ["exercise1.cc"],
    hdrs = ["exercise1.h"],
    tags = [
        "manual",
        "nobuilder",
    ],
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
    srcs = ["exercise1_test.cc"],
    tags = EXERCISE_TEST_TAGS,
    deps = [
        ":exercise1",
        "//internal:testing",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "exercise2",
    srcs = ["exercise2.cc"],
    hdrs = ["exercise2.h"],
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
    srcs = ["exercise2_test.cc"],
    tags = EXERCISE_TEST_TAGS,
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
    tags = EXERCISE_TEST_TAGS,
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
    name = "checked_expr_conversion_example",
    hdrs = ["checked_expr_conversion_example.h"],
    deps = [
        "//common:ast",
        "//common:ast_proto",
        "//internal:status_macros",
        "@com_google_absl//absl/status:statusor",
        "@com_google_cel_spec//proto/cel/expr:checked_cc_proto",
    ],
)

cc_test(
    name = "checked_expr_conversion_example_test",
    srcs = ["checked_expr_conversion_example_test.cc"],
    deps = [
        ":checked_expr_conversion_example",
        "//checker:validation_result",
        "//common:ast",
        "//compiler",
        "//compiler:compiler_factory",
        "//compiler:standard_library",
        "//internal:testing",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_cel_spec//proto/cel/expr:checked_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "exercise4",
    srcs = ["exercise4.cc"],
    hdrs = ["exercise4.h"],
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
    srcs = ["exercise4_test.cc"],
    tags = EXERCISE_TEST_TAGS,
    deps = [
        ":exercise4",
        "//internal:testing",
        "@com_google_googleapis//google/rpc/context:attribute_context_cc_proto",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:struct_cc_proto",
    ],
)

cc_library(
    name = "network_functions",
    srcs = ["network_functions.cc"],
    hdrs = ["network_functions.h"],
    deps = [
        "//checker:type_checker_builder",
        "//common:decl",
        "//common:native_type",
        "//common:type",
        "//common:typeinfo",
        "//common:value",
        "//compiler",
        "//internal:status_macros",
        "//runtime:function_adapter",
        "//runtime:function_registry",
        "//runtime:runtime_options",
        "//runtime:type_registry",
        "@com_google_absl//absl/base:no_destructor",
        "@com_google_absl//absl/base:nullability",
        "@com_google_absl//absl/log:absl_check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:string_view",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "network_functions_test",
    srcs = ["network_functions_test.cc"],
    deps = [
        ":network_functions",
        "//common:decl",
        "//common:minimal_descriptor_pool",
        "//common:type",
        "//common:value",
        "//compiler",
        "//compiler:compiler_factory",
        "//compiler:standard_library",
        "//internal:benchmark",
        "//internal:status_macros",
        "//internal:testing",
        "//runtime",
        "//runtime:activation",
        "//runtime:constant_folding",
        "//runtime:runtime_options",
        "//runtime:standard_runtime_builder_factory",
        "@com_google_absl//absl/log:absl_check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "exercise10",
    srcs = ["exercise10.cc"],
    hdrs = ["exercise10.h"],
    deps = [
        ":network_functions",
        "//checker:validation_result",
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
    srcs = ["exercise10_test.cc"],
    tags = EXERCISE_TEST_TAGS,
    deps = [
        ":exercise10",
        "//internal:testing",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
    ],
)
