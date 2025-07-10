
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
        sha256 = "c29445732e8015be153b84531deb43c6e31581bdf7d97328108b55e081c164c3",
        strip_prefix = "envoy-openssl-3396212a4d0e866e1f245bcfdc3ddc9815ee68ee",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/3396212a4d0e866e1f245bcfdc3ddc9815ee68ee.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
