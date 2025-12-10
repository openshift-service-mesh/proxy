
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
        sha256 = "9892be377e6e29b886fc1225ebb5e470dc82709e264867d5c874ac8322cd4ac7",
        strip_prefix = "envoy-openssl-f348aedd10253ca0ca49721ffdc332e56cb89bf1",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/f348aedd10253ca0ca49721ffdc332e56cb89bf1.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
