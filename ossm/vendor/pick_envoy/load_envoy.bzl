
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
        sha256 = "a4c93c0e0e3937f8c4606f39ccf7be115da73e25062d7eb0ef683c738494d1d6",
        strip_prefix = "envoy-openssl-ae2d794627436da87a38aafe4240cd1c29223601",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/ae2d794627436da87a38aafe4240cd1c29223601.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
