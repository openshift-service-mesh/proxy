
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
        sha256 = "5f3706775bbc495cb34db3810cdf7bd8b8352e2d274a5f55ddb6eaf8b56d7f66",
        strip_prefix = "envoy-openssl-073e4cb3b30c72b2e0b5ce51cee2bc8eb4be0643",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/073e4cb3b30c72b2e0b5ce51cee2bc8eb4be0643.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
