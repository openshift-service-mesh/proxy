
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
        sha256 = "dea8551758eeb7547476a6f432d2d3d0794bcca0f4f56610e7e9b0bb38c9590c",
        strip_prefix = "envoy-openssl-20c9fba150c76094fc8e8c40379cd44ac35f3df1",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/20c9fba150c76094fc8e8c40379cd44ac35f3df1.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
