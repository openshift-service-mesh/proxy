
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
        sha256 = "94b673a9f1a34da6fc38a851ca77b2372378efa6df36e3d2efc7f36075e13ac2",
        strip_prefix = "envoy-openssl-4c977577f97ce9a86812d59291d8839ebfa471e0",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/4c977577f97ce9a86812d59291d8839ebfa471e0.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
