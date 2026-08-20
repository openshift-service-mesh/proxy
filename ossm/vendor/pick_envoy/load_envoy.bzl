
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
        sha256 = "d1602c447ee3e8c9908b26c487d6054ade5783dd044876b308f68a54bdee355f",
        strip_prefix = "envoy-openssl-455f77e7c8f2d590f99e0c13ac54820a04b97773",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/455f77e7c8f2d590f99e0c13ac54820a04b97773.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
