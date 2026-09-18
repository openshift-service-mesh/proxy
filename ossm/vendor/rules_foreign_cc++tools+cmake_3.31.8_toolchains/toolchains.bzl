def register_toolchains():
    native.register_toolchain(
    "@cmake-3.31.8-linux-aarch64//:cmake_tool",
    "@cmake-3.31.8-linux-x86_64//:cmake_tool",
    "@cmake-3.31.8-macos-universal//:cmake_tool",
    "@cmake-3.31.8-windows-i386//:cmake_tool",
    "@cmake-3.31.8-windows-x86_64//:cmake_tool",
    )
