# Copyright 2019 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@com_google_protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("//bazel:grpc_build_system.bzl", "grpc_internal_proto_library")
load("//bazel:cc_grpc_library.bzl", "cc_grpc_library")

# TODO(rishesh): Enable parse_headers when internal build system limitations are resolved.
package(features = [
    "layering_check",
    # "parse_headers",
])

licenses(["notice"])

grpc_internal_proto_library(
    name = "alts_handshaker_proto",
    srcs = [
        "altscontext.proto",
        "handshaker.proto",
        "transport_security_common.proto",
    ],
    visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "alts_handshaker_cc_proto",
    deps = [":alts_handshaker_proto"],
)

cc_grpc_library(
    name = "alts_handshaker_cc_grpc",
    srcs = [":alts_handshaker_proto"],
    deps = [
        ":alts_handshaker_cc_proto",
        "//:grpc++_public_hdrs",
    ],
    grpc_only = True,
    visibility = ["//visibility:public"],
)
