
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
        sha256 = "7d8eb5c52e381d8bfd4300a2572b542662be1aec724361349f21f9aca108b271",
        strip_prefix = "envoy-openssl-42f6ee3214b3ac45892d5701e659c2387a6a34f2",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/42f6ee3214b3ac45892d5701e659c2387a6a34f2.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
