
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
        sha256 = "9fae798a3055c2a51312274aafa9b6d00ae5f9dc14ae459c5a54468fa27c3d78",
        strip_prefix = "envoy-openssl-fae3292695b38196207d5e39283eb47662e8e0f5",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/fae3292695b38196207d5e39283eb47662e8e0f5.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
