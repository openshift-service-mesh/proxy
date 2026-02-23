
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
        sha256 = "2917c0a1bf73b300c537fd5d57ff0884df6bea2eb7d969d37480f1a766d478d6",
        strip_prefix = "envoy-openssl-a5ae374fe7dfe7ed547d009a670f6e3d23b7ce43",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/a5ae374fe7dfe7ed547d009a670f6e3d23b7ce43.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
