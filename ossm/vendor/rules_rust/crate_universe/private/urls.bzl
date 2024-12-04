"""A file containing urls and associated sha256 values for cargo-bazel binaries

This file is auto-generated for each release to match the urls and sha256s of
the binaries produced for it.
"""

# Example:
# {
#     "x86_64-unknown-linux-gnu": "https://domain.com/downloads/cargo-bazel-x86_64-unknown-linux-gnu",
#     "x86_64-apple-darwin": "https://domain.com/downloads/cargo-bazel-x86_64-apple-darwin",
#     "x86_64-pc-windows-msvc": "https://domain.com/downloads/cargo-bazel-x86_64-pc-windows-msvc",
# }
CARGO_BAZEL_URLS = {
  "aarch64-apple-darwin": "https://github.com/bazelbuild/rules_rust/releases/download/0.51.0/cargo-bazel-aarch64-apple-darwin",
  "aarch64-pc-windows-msvc": "https://github.com/bazelbuild/rules_rust/releases/download/0.51.0/cargo-bazel-aarch64-pc-windows-msvc.exe",
  "aarch64-unknown-linux-gnu": "https://github.com/bazelbuild/rules_rust/releases/download/0.51.0/cargo-bazel-aarch64-unknown-linux-gnu",
  "x86_64-apple-darwin": "https://github.com/bazelbuild/rules_rust/releases/download/0.51.0/cargo-bazel-x86_64-apple-darwin",
  "x86_64-pc-windows-gnu": "https://github.com/bazelbuild/rules_rust/releases/download/0.51.0/cargo-bazel-x86_64-pc-windows-gnu.exe",
  "x86_64-pc-windows-msvc": "https://github.com/bazelbuild/rules_rust/releases/download/0.51.0/cargo-bazel-x86_64-pc-windows-msvc.exe",
  "x86_64-unknown-linux-gnu": "https://github.com/bazelbuild/rules_rust/releases/download/0.51.0/cargo-bazel-x86_64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl": "https://github.com/bazelbuild/rules_rust/releases/download/0.51.0/cargo-bazel-x86_64-unknown-linux-musl"
}

# Example:
# {
#     "x86_64-unknown-linux-gnu": "1d687fcc860dc8a1aa6198e531f0aee0637ed506d6a412fe2b9884ff5b2b17c0",
#     "x86_64-apple-darwin": "0363e450125002f581d29cf632cc876225d738cfa433afa85ca557afb671eafa",
#     "x86_64-pc-windows-msvc": "f5647261d989f63dafb2c3cb8e131b225338a790386c06cf7112e43dd9805882",
# }
CARGO_BAZEL_SHA256S = {
  "aarch64-apple-darwin": "604190df2967941f735c3b9a6a0ba92e6c826379b0a49bb00ec9cf61af59392d",
  "aarch64-pc-windows-msvc": "ebf3868853219cc107107af554562f377937543330fae42e3e1efcdb8f79fc64",
  "aarch64-unknown-linux-gnu": "4e2cba0e871e0a3412459f73e85e8ee7091a43c98b8b86722e8c7dcdf5ffa08e",
  "x86_64-apple-darwin": "0de69294b78503d9fde35a84e31aba24d503da74a5ef0416ee1c8d49ec5029ca",
  "x86_64-pc-windows-gnu": "b1b9158564497b13a9ff0a72793ff4497ec9572e3b8df7258e9f74f4e4aed810",
  "x86_64-pc-windows-msvc": "1665532ee718c883fe61be71bcf584aa759c75fe6dc431b481adfa823a38d647",
  "x86_64-unknown-linux-gnu": "7ec5837a46305a71560d5bb051abaa12d968c8cbea0a39922a3b575bdc50c3ac",
  "x86_64-unknown-linux-musl": "b2a0677ab0c3ccf8f1c46f172ec65f12856bcb9b99d4ed4c484b765490f8579f"
}

# Example:
# Label("//crate_universe:cargo_bazel_bin")
CARGO_BAZEL_LABEL = Label("//crate_universe:cargo_bazel_bin")
