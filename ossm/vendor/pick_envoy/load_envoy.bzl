
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
        sha256 = "3377ac95608e9c3db9c4480f9bf5aa9480d4aa8c62dd9b7382d9a0ca36e6b5b2",
        strip_prefix = "envoy-openssl-8b1cbcbbaf8c4a6f9fc578dc59c2d08fd206450c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/8b1cbcbbaf8c4a6f9fc578dc59c2d08fd206450c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
