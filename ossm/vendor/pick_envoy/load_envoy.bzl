
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
        sha256 = "b7da19bd644fcf35d4a6899870c33d186a529ef5bdd25a4be4119870e40d5376",
        strip_prefix = "envoy-openssl-e4a12b3aef36162f676d5c37494d243b7f0db96f",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/e4a12b3aef36162f676d5c37494d243b7f0db96f.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
