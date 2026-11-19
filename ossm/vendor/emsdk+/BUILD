package(default_visibility = ["//visibility:public"])

filegroup(name = "empty")

alias(
    name = "dwp_files",
    actual = select({
        ":linux": "@emscripten_bin_linux//:dwp_files",
        ":linux_arm64": "@emscripten_bin_linux_arm64//:dwp_files",
        ":macos": "@emscripten_bin_mac//:dwp_files",
        ":macos_arm64": "@emscripten_bin_mac_arm64//:dwp_files",
        ":windows": "@emscripten_bin_win//:dwp_files",
        "//conditions:default": ":empty",
    }),
)

platform(
    name = "platform_wasm",
    constraint_values = [
        "@platforms//cpu:wasm32",
        "@platforms//os:emscripten",
    ],
)

platform(
    name = "platform_wasi",
    constraint_values = [
        "@platforms//cpu:wasm32",
        "@platforms//os:wasi",
    ],
)
