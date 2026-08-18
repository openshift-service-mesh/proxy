
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
        sha256 = "fd1f0c7c9a834c5e8022773135d32138f00ede194069eaa2c8aa235a26704ead",
        strip_prefix = "envoy-openssl-c2f880685e23cb5e51ed167041ad511d5bb38a22",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/c2f880685e23cb5e51ed167041ad511d5bb38a22.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
