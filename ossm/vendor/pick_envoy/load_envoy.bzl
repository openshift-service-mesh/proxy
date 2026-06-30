
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
        sha256 = "e21cb6c65f74125a29fc9325840fe5951d2caed6258ba70098222875df1e57ce",
        strip_prefix = "envoy-openssl-89baea2439f0f16c86940f1849ad1a748eb5732a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/89baea2439f0f16c86940f1849ad1a748eb5732a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
