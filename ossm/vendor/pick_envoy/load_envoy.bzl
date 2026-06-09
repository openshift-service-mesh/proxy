
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
        sha256 = "b36707bddd80660fb106c5d2bdfccc0991961d5665db2530685ae8efc446c9e3",
        strip_prefix = "envoy-openssl-7775ce1066168ba7b6b221ae742644ac4ce74b8b",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7775ce1066168ba7b6b221ae742644ac4ce74b8b.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
