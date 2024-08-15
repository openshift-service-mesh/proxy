
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
        sha256 = "d3ca2e8d3b3a2effeb092f8ecd2a09a4fc2fd3188abdd0a558d20a58107c106e",
        strip_prefix = "envoy-openssl-3677e06b8750ab1b46637256029a82266f9e5b31",
        url = "https://github.com/dcillera/envoy-openssl/archive/3677e06b8750ab1b46637256029a82266f9e5b31.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
