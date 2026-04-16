
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
        sha256 = "5f31a570a0916aa527a6092da71c82ac4fc21150b5da57d9bf136a492bc7a3c8",
        strip_prefix = "envoy-openssl-aa6b77582e2507f6dff2c613b7c973857690b27e",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/aa6b77582e2507f6dff2c613b7c973857690b27e.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
