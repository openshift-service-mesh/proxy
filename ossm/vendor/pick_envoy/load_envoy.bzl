
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
        sha256 = "bbeadc4872e764d336430f949f1803f73c60c3f1f49c92825332ae94b25b4cff",
        strip_prefix = "envoy-openssl-2eadb07525a95a56dd663ea6d64150bfb37d7a7a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/2eadb07525a95a56dd663ea6d64150bfb37d7a7a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
