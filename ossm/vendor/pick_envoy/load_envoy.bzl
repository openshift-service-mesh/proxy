
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
        sha256 = "1ca7a9029d8c0045a6226ac80142112f484f18eb3c3304e4675fdaf3459e7176",
        strip_prefix = "envoy-openssl-a8b39d83f851500874ad37b2701b0530d3bd3149",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/a8b39d83f851500874ad37b2701b0530d3bd3149.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
