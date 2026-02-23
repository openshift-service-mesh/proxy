
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
        sha256 = "6870689c05921e2b12e37292883dc4ad07d3889b3dc09917476922a7f930c704",
        strip_prefix = "envoy-openssl-9f7814ee2d5d9c07a1d029abc8e1a20444ada214",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/9f7814ee2d5d9c07a1d029abc8e1a20444ada214.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
