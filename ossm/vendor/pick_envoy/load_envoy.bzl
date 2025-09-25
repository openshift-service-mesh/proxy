
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
        sha256 = "c7ef81995aaa7e13bf7973055585117329a8465b4cd14295edc88dcb3411bda6",
        strip_prefix = "envoy-openssl-e4af21e4650d326fdc7d2cc3b605ce2398461af8",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/e4af21e4650d326fdc7d2cc3b605ce2398461af8.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
