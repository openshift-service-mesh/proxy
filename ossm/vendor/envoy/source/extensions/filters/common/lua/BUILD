load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)
load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")

licenses(["notice"])  # Apache 2

# Build setting to choose between luajit (default) and luajit2 (for s390x/ppc)
bool_flag(
    name = "luajit2",
    build_setting_default = False,
    visibility = ["//visibility:public"],
)

# Configuration setting for luajit2
config_setting(
    name = "use_luajit2",
    flag_values = {":luajit2": "True"},
    visibility = ["//visibility:public"],
)

envoy_extension_package()

envoy_cc_library(
    name = "lua_lib",
    srcs = ["lua.cc"],
    hdrs = ["lua.h"],
    deps = [
    ] + select({
        ":use_luajit2": ["//bazel/foreign_cc:luajit2"],
        "//conditions:default": ["//bazel/foreign_cc:luajit"],
    }) + [
        "//envoy/thread_local:thread_local_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:c_smart_ptr_lib",
        "//source/common/common:lock_guard_lib",
        "//source/common/common:thread_lib",
        "//source/common/protobuf",
    ],
)

envoy_cc_library(
    name = "wrappers_lib",
    srcs = ["wrappers.cc"],
    hdrs = ["wrappers.h"],
    deps = [
        ":lua_lib",
        "//envoy/buffer:buffer_interface",
        "//source/common/common:hex_lib",
        "//source/common/protobuf",
    ],
)

envoy_cc_library(
    name = "protobuf_converter_lib",
    srcs = ["protobuf_converter.cc"],
    hdrs = ["protobuf_converter.h"],
    deps = [
        ":lua_lib",
    ] + select({
        ":use_luajit2": ["//bazel/foreign_cc:luajit2"],
        "//conditions:default": ["//bazel/foreign_cc:luajit"],
    }) + [
        "//source/common/protobuf",
        "//source/common/protobuf:create_reflectable_message_lib",
        "//source/common/protobuf:utility_lib",
        "@abseil-cpp//absl/strings",
    ],
)
