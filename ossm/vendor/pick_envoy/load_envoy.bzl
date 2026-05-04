
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
        sha256 = "ea8b18576decb9c5a18c63f80c9fb9c6109cf4d4de6041365fe0aad742fe340f",
        strip_prefix = "envoy-openssl-54afcc649ba29597a36a3d84c663a34e597d5bc2",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/54afcc649ba29597a36a3d84c663a34e597d5bc2.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
