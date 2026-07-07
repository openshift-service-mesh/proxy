
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
        sha256 = "c55be74f7cf67634441d85de65604dc542bef9dfa818bbfe5d69f3640aaa48b8",
        strip_prefix = "envoy-openssl-a1be1bed8c9ca18d3ebc4760b266e6a13d380fa7",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/a1be1bed8c9ca18d3ebc4760b266e6a13d380fa7.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
