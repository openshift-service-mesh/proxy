
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
        sha256 = "47b12dae03329d48f02f84d4d0c944eab4ee764e2ac46631ca0287fb081b1e18",
        strip_prefix = "envoy-openssl-15eb167b860ed07103a6616f83d90fab9b484e8d",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/15eb167b860ed07103a6616f83d90fab9b484e8d.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
