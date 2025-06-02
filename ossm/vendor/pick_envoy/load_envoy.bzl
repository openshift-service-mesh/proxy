
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
        sha256 = "49f1cca7fd2ff4c973ccda02a1dae99418d7357264bb0fe0a1e441ef929a9dfb",
        strip_prefix = "envoy-openssl-e7b3303315726b224556387579f2330a1a1bf7a4",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/e7b3303315726b224556387579f2330a1a1bf7a4.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
