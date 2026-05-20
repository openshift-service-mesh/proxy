
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
        sha256 = "2d11bac624798ec154d19e4f068d395b6e927e66e28ff0e7d462521d3e6bb368",
        strip_prefix = "envoy-openssl-9f23d180d856f25e4557db679ec5e424ee7f4f24",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/9f23d180d856f25e4557db679ec5e424ee7f4f24.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
