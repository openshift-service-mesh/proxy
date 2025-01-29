
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
        sha256 = "6b2af51db2d9954a1ac2b03e66fb199825f0d3120c43fde72c46b58c8b93ddf6",
        strip_prefix = "envoy-openssl-aaaa6466581eb1be1c422f286f34f19f7a09d271",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/aaaa6466581eb1be1c422f286f34f19f7a09d271.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
