
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
        sha256 = "aea8cbed31ad7d7a571cb9b420e32358d58bc23fdbf12e2e58ad3c77d7141ab8",
        strip_prefix = "envoy-openssl-87a927b44d5f93c189850bee8c6ed5468959ee0a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/87a927b44d5f93c189850bee8c6ed5468959ee0a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
