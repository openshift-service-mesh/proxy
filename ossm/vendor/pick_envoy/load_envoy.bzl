
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
        sha256 = "765112666e3a89f958a9ee8563687c1c7c1cc25fd1a0a35123be76dac50c6fa3",
        strip_prefix = "envoy-openssl-587248c867aa97c7cacbd7ffbbdaf76447ba2c6a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/587248c867aa97c7cacbd7ffbbdaf76447ba2c6a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
