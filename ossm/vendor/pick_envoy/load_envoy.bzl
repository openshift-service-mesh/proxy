
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
        sha256 = "83bacc065c0f7628025fb0a66f0563d8e445b39b953f02964286a58e1cb8e0a2",
        strip_prefix = "envoy-openssl-122c20ab8fe6dd675338ae414ef6371f03b1f577",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/122c20ab8fe6dd675338ae414ef6371f03b1f577.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
