
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
        sha256 = "dbb5e16869d17b0aca0c3ece7072a1ec70523b11da94aa152dd5a8f39d0e3beb",
        strip_prefix = "envoy-openssl-1219b634d87e1548352551d43593a959e83cfcf5",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/1219b634d87e1548352551d43593a959e83cfcf5.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
