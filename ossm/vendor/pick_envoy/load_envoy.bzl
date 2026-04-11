
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
        sha256 = "1abdb49a4a4f8a5921e84d67af0c123464e4a0a159e9e037102e353a33f26c3b",
        strip_prefix = "envoy-openssl-a86f6651d92edb2472ca7bf967f840368f2aee46",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/a86f6651d92edb2472ca7bf967f840368f2aee46.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
