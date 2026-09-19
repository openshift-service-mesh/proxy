
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

OPENSSL_DISABLED_EXTENSIONS = [
            "envoy.tls.key_providers.cryptomb",
            "envoy.tls.key_providers.qat",
            "envoy.quic.deterministic_connection_id_generator",
            "envoy.quic.crypto_stream.server.quiche",
            "envoy.quic.proof_source.filter_chain",
        ]

def load_envoy():
    http_archive(
        name = "envoy",
        sha256 = "d514db7405f4e96ad1928868851cb0ccfbf131b857de128d19a7a1b072b3a5a8",
        strip_prefix = "envoy-openssl-5685e29e07d126033e30668e7f6bc3de971e8c34",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/5685e29e07d126033e30668e7f6bc3de971e8c34.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
