
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
        sha256 = "30244b6b54df2d9e9d6ce12e7a36ef7eb394b7d19bacbb71e8555b8a33647b92",
        strip_prefix = "envoy-openssl-8ac90383a0a131403572ff70b5f6c9597e3c36d6",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/8ac90383a0a131403572ff70b5f6c9597e3c36d6.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
