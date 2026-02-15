
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
        sha256 = "d8cfa378d12ea634688cc6c73b2d42514daffac6fee2025539a1098c599980c0",
        strip_prefix = "envoy-openssl-afd341decd4f5a56d1eec4e9d9ababf66733267e",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/afd341decd4f5a56d1eec4e9d9ababf66733267e.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
