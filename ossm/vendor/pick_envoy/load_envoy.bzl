
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
        sha256 = "57f6d6c979b5ea0012c77f4c2b378c2c048f54c8784a2d8fa0b5cacc230b0179",
        strip_prefix = "envoy-openssl-7be14e89d5adb27476bdb61b6549e34780dec1ee",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7be14e89d5adb27476bdb61b6549e34780dec1ee.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
