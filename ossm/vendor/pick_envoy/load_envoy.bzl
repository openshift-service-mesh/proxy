
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
        sha256 = "dd53535119ce11673df7b922c38a50a3d421ae106c054b15ccaf39391dc0b3b5",
        strip_prefix = "envoy-openssl-eea6de0eaaf933ee45aaf179bfdcf1371e9f543e",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/eea6de0eaaf933ee45aaf179bfdcf1371e9f543e.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
