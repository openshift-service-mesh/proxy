
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
        sha256 = "2edba4dbe809f38c696c0d247ba8f008a863835d75f67a6fe5c45f241e03a553",
        strip_prefix = "envoy-openssl-81821087273f2ad18fb717c5906e239635861d3f",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/81821087273f2ad18fb717c5906e239635861d3f.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
