
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
        sha256 = "8508246cf2ae25e25b1bc96857d995241e9a7999150886aac0ac4ec245e9551a",
        strip_prefix = "envoy-openssl-6cacd8cdb13adb8ab3a2fb81e34b461d9de10a2c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/6cacd8cdb13adb8ab3a2fb81e34b461d9de10a2c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
