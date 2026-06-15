
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
        sha256 = "db0d4ef25dd23a6a0ae3b1752d556e02d1ba91c0498043cf8a2f239b265136c9",
        strip_prefix = "envoy-openssl-69f4eedb72f389eaf9e0b43371e6fa22ff419387",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/69f4eedb72f389eaf9e0b43371e6fa22ff419387.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
