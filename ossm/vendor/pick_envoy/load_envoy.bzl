
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
        sha256 = "e7df59001c3d22ca19de01ee1e2c3c4bc7e00bd6551231e7ca78815198d82fc1",
        strip_prefix = "envoy-openssl-056b17ae957ffb6349059eef2d72cabf79c925d0",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/056b17ae957ffb6349059eef2d72cabf79c925d0.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
