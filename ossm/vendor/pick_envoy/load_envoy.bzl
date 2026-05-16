
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
        sha256 = "e62b59537fee1dce5359da7a457de2254e6968c90b61bfd7d6a98591b444298e",
        strip_prefix = "envoy-openssl-096edd5d67d2c7f6babe2b4a1f82f704b3e3240a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/096edd5d67d2c7f6babe2b4a1f82f704b3e3240a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
