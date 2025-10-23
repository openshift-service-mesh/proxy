
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
        sha256 = "dd5aa0570a9072b43934250b8e8668b18c560e96c4664a5e0a6f334012208dbe",
        strip_prefix = "envoy-openssl-107d692cd6df61f0fab5d0d76468a895068db9a9",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/107d692cd6df61f0fab5d0d76468a895068db9a9.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
