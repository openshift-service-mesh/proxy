"""Manifest of prebuilt tool binaries for this release."""

ARTIFACTS_MANIFEST_JSON = """
{
 "artifacts": {
  "exe_zip_maker": [
   {
    "exec_compatible_with": [
     "@platforms//cpu:aarch64",
     "@platforms//os:macos"
    ],
    "name": "exe_zip_maker_aarch64_apple_darwin",
    "sha256": "3729afc7e4f749ea69a8dc5efcc4688439cd17b2558ef03e4df96d68888fd067",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-aarch64-apple-darwin"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:aarch64",
     "@platforms//os:windows"
    ],
    "name": "exe_zip_maker_aarch64_pc_windows_msvc",
    "sha256": "4a3157bc4bc2b9b26af92b2899180771e4e87a52dba07f64257f58f3c9331b78",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-aarch64-pc-windows-msvc.exe"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:aarch64",
     "@platforms//os:linux"
    ],
    "name": "exe_zip_maker_aarch64_unknown_linux_musl",
    "sha256": "3439a694eba05ee3e266a7217c1e797b68f6e469880af3e434b3976f6eaf8fa1",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-aarch64-unknown-linux-musl"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:armv7",
     "@platforms//os:linux"
    ],
    "name": "exe_zip_maker_armv7_unknown_linux_musleabihf",
    "sha256": "a04d864b669cad8d74413c5245bbc06ba8b1ee47662903494c323d7eadc60968",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-armv7-unknown-linux-musleabihf"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:x86_32",
     "@platforms//os:windows"
    ],
    "name": "exe_zip_maker_i686_pc_windows_msvc",
    "sha256": "c07791e8748dd175420185945deb5737ef04b57c891301f7883aeae75bcb3444",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-i686-pc-windows-msvc.exe"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:x86_32",
     "@platforms//os:linux"
    ],
    "name": "exe_zip_maker_i686_unknown_linux_musl",
    "sha256": "0d83b7636a3ad59e9b01e217b476d33304096f1ab85b5daba9924ef17e8e3ede",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-i686-unknown-linux-musl"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:ppc64le",
     "@platforms//os:linux"
    ],
    "name": "exe_zip_maker_powerpc64le_unknown_linux_musl",
    "sha256": "46be5feb6070a25dce94448275f2809ea8e6e8a5a51622660a675b0ea79f35eb",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-powerpc64le-unknown-linux-musl"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:riscv64",
     "@platforms//os:linux"
    ],
    "name": "exe_zip_maker_riscv64gc_unknown_linux_musl",
    "sha256": "c4cfeba395288e56bb4a4c09b681d7a8625189542e4bf5edc7cc348b51deec6a",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-riscv64gc-unknown-linux-musl"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:x86_64",
     "@platforms//os:macos"
    ],
    "name": "exe_zip_maker_x86_64_apple_darwin",
    "sha256": "3f78dbfa020f48e2156acd57b42972af660a02a87c05dc650a373bc7ce39a014",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-x86_64-apple-darwin"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:x86_64",
     "@platforms//os:windows"
    ],
    "name": "exe_zip_maker_x86_64_pc_windows_msvc",
    "sha256": "58503fcb7275e872d6dc5aa0fbd9faac2cbfe54ff1417651722e65fc9528c2b9",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-x86_64-pc-windows-msvc.exe"
    ]
   },
   {
    "exec_compatible_with": [
     "@platforms//cpu:x86_64",
     "@platforms//os:linux"
    ],
    "name": "exe_zip_maker_x86_64_unknown_linux_gnu",
    "sha256": "52f9eabf8ae76bba6aa2607d1bbbc786a45ddfb56976b8b8ecf811193770b7fc",
    "urls": [
     "https://github.com/bazel-contrib/rules_python/releases/download/2.5.1/exe_zip_maker-x86_64-unknown-linux-gnu"
    ]
   }
  ]
 }
}
"""
