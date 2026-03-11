
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
        sha256 = "0e52dc4b181a135b9cd410c052942ad85d117f5a10f1f08e9a92f9146611c888",
        strip_prefix = "envoy-openssl-6fa686fffda9835b47c417de391bcafdd415cfe5",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/6fa686fffda9835b47c417de391bcafdd415cfe5.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
