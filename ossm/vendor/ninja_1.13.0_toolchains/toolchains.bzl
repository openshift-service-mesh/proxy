def register_toolchains():
    native.register_toolchain(
    "@ninja_1.13.0_linux//:ninja_tool",
    "@ninja_1.13.0_linux-aarch64//:ninja_tool",
    "@ninja_1.13.0_mac//:ninja_tool",
    "@ninja_1.13.0_mac_aarch64//:ninja_tool",
    "@ninja_1.13.0_win//:ninja_tool",
    )
