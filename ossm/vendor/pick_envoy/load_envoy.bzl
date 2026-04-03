
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
        sha256 = "d7e03e42b56528b6e2950b4d20de29b3f5382ddf1ca313b83c46c7d6790ed716",
        strip_prefix = "envoy-openssl-9ca26e2da0295ae73ab0f545dbbd694a73a22aae",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/9ca26e2da0295ae73ab0f545dbbd694a73a22aae.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
