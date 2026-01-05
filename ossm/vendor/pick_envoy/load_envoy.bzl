
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
        sha256 = "d4f4dcdd48c3aa8d5108846d3b5d9727062f32b12dff41fd6b7d86a8912a627b",
        strip_prefix = "envoy-openssl-95ec4e8e203a83969f2b667377a75cb57bc427f2",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/95ec4e8e203a83969f2b667377a75cb57bc427f2.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
