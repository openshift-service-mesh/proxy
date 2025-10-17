
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
        sha256 = "6c109fd25d59356eb64776e42f3b7c72b2b5e5bf8a99026f2cc8664f1321eaf8",
        strip_prefix = "envoy-openssl-7fbbde6734508bc4666fbf2e4cb2b6cc6c157e1d",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7fbbde6734508bc4666fbf2e4cb2b6cc6c157e1d.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
