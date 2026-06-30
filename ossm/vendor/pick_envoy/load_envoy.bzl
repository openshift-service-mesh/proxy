
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
        sha256 = "60af6a1d6294689fcef36671e29c9e28e3fb8ce4bc0dfe349be88b14166d8e50",
        strip_prefix = "envoy-openssl-c172f9ec114328b4f6a92e9904733158a1d6bfe1",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/c172f9ec114328b4f6a92e9904733158a1d6bfe1.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
