# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@bazel_skylib//lib:selects.bzl", "selects")
load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load(":v8_transition.bzl", "v8_lib_no_pointer_compression")

package(default_visibility = ["//visibility:public"])

# Engine selection flag, replacing the legacy --define engine=<value>.
# Values:
#   v8          - V8 Wasm engine (default)
#   wamr        - WebAssembly Micro Runtime, interpreter mode
#   wamr-interp - WebAssembly Micro Runtime, interpreter mode
#   wamr-jit    - WebAssembly Micro Runtime, JIT mode
#   wasmtime    - Wasmtime engine
#   wasmedge    - WasmEdge engine
#   null        - Null (no-op) engine
#   disabled    - No engine; disables all wasm functionality
#   multi       - Multiple engines
string_flag(
    name = "engine",
    build_setting_default = "v8",
    values = [
        "v8",
        "wamr",
        "wamr-interp",
        "wamr-jit",
        "wasmtime",
        "wasmedge",
        "null",
        "disabled",
        "multi",
    ],
)

config_setting(
    name = "engine_null",
    flag_values = {"//bazel:engine": "null"},
)

config_setting(
    name = "engine_v8",
    flag_values = {"//bazel:engine": "v8"},
)

# engine_wamr_interp matches both "wamr-interp" and the generic "wamr" alias.
config_setting(
    name = "_engine_wamr_interp_strict",
    flag_values = {"//bazel:engine": "wamr-interp"},
)

config_setting(
    name = "engine_wamr",
    flag_values = {"//bazel:engine": "wamr"},
)

selects.config_setting_group(
    name = "engine_wamr_interp",
    match_any = [
        ":_engine_wamr_interp_strict",
        ":engine_wamr",
    ],
)

config_setting(
    name = "engine_wamr_jit",
    flag_values = {"//bazel:engine": "wamr-jit"},
)

config_setting(
    name = "engine_wasmedge",
    flag_values = {"//bazel:engine": "wasmedge"},
)

config_setting(
    name = "engine_wasmtime",
    flag_values = {"//bazel:engine": "wasmtime"},
)

config_setting(
    name = "multiengine",
    flag_values = {"//bazel:engine": "multi"},
)

config_setting(
    name = "engine_disabled",
    flag_values = {"//bazel:engine": "disabled"},
)

config_setting(
    name = "requested_crypto_system",
    values = {"define": "crypto=system"},
)

config_setting(
    name = "linux_s390x",
    values = {"cpu": "s390x"},
)

selects.config_setting_group(
    name = "crypto_system",
    match_any = [
        ":requested_crypto_system",
        ":linux_s390x",
    ],
)

# V8 library with pointer compression disabled using V8's Starlark transition.
# This avoids the need to patch V8's default pointer compression setting.
v8_lib_no_pointer_compression(
    name = "wee8_no_pointer_compression",
    library = "@v8//:wee8",
)

exports_files(["tsan_suppressions.txt"])
