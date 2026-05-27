
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
        sha256 = "7d0cd4ae1a6730dcbdee3580ddb49bacdc684543e48d6879d6efcf7ff0ed495d",
        strip_prefix = "envoy-openssl-4cd2547b89c546a6d0334045a97c092afdb82624",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/4cd2547b89c546a6d0334045a97c092afdb82624.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
