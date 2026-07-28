
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
        sha256 = "2ea02c01dd4bfb8cf807a29c02209f92d2de482b13cafec09976302e845216ff",
        strip_prefix = "envoy-openssl-05623c10e47b919eb9ffe647ba8b8f7a775a25a5",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/05623c10e47b919eb9ffe647ba8b8f7a775a25a5.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
