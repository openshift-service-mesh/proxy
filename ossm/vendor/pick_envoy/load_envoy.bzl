
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
        sha256 = "1ee56e9bbae4e730a519273c17521df342308d41b6b4523ca70c81d0ff724ed8",
        strip_prefix = "envoy-openssl-7231aafe01f8d1c985cfc7920f3b45200a85a7f5",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7231aafe01f8d1c985cfc7920f3b45200a85a7f5.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
