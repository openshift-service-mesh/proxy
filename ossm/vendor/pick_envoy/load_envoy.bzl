
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
        sha256 = "e1a6278dc6ee982bb1e4ee1539d8c702675a570edc2fd2f282a0d695a8dcf1ea",
        strip_prefix = "envoy-openssl-1dde15e236e31b8bd132ab872022916516a3adde",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/1dde15e236e31b8bd132ab872022916516a3adde.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
