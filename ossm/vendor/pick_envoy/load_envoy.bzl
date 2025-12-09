
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
        sha256 = "815957d0e6515d55f455c9a793873302c16909b4ddc4e03b2fbd363a2786d67b",
        strip_prefix = "envoy-openssl-6c17467b9187b83a641702d1ec09b9663ac1b6f3",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/6c17467b9187b83a641702d1ec09b9663ac1b6f3.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
