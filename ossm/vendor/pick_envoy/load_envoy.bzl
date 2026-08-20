
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
        sha256 = "d514f9e4a1fa6f13fe545811e82fa3f9b4c89f8bef8e30fbb87001d52478e228",
        strip_prefix = "envoy-openssl-a582148c82937dd76ec9939483a4e1a0a20e8aa3",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/a582148c82937dd76ec9939483a4e1a0a20e8aa3.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
