
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
        sha256 = "ecd76f6f64ccf1f859a817921faa4bfca70c7aa73155e0399ba43f3351fd6514",
        strip_prefix = "envoy-openssl-577fa358736f993c0bf754f21917b43fcd6f151b",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/577fa358736f993c0bf754f21917b43fcd6f151b.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
