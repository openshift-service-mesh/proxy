
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
        sha256 = "44863ae27bfb9acaa1679f664a07d2b127b87c60600c804d8e8742b980f90a21",
        strip_prefix = "envoy-openssl-a040a5fd15b82dc07ecb227036caaaa844ef787c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/a040a5fd15b82dc07ecb227036caaaa844ef787c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
