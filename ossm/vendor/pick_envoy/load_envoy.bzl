
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
        sha256 = "581bef4e468b1b7b4f0e38671d417337cbb1f77929506092a10fe9f4e58013e5",
        strip_prefix = "envoy-openssl-c3a37ca03c0bb662e2098a677d9f66f63f11f2dc",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/c3a37ca03c0bb662e2098a677d9f66f63f11f2dc.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
