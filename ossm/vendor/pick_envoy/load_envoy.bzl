
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
        sha256 = "8aa3a919b0056973ad6994c39a1614095c775f26ad45943b627621189b7bbd53",
        strip_prefix = "envoy-openssl-1921d0dbfa9ab1cc521964b53afa4ea1b6c25e05",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/1921d0dbfa9ab1cc521964b53afa4ea1b6c25e05.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
