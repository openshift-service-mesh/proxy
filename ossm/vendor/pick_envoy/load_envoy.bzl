
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
        sha256 = "f60abad4d2f5fa6dc3e074972d0068479e74117ca1347d029be9176f409a631d",
        strip_prefix = "envoy-openssl-beeef78bc0dd1b72e5a50cb9c5681dcab1888887",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/beeef78bc0dd1b72e5a50cb9c5681dcab1888887.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
