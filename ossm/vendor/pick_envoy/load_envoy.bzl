
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
        sha256 = "81b3e5fa39815d5bf4998f4c3de39a2ada405c01ca72eb8ffd96a32ec1a4d91d",
        strip_prefix = "envoy-openssl-ca1d6e76e00fa798f5b2853b6c0d424fd1686bb5",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/ca1d6e76e00fa798f5b2853b6c0d424fd1686bb5.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
