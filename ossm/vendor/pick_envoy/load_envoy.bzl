
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
        sha256 = "ade15894836bf082aa2cf732c45784f89cc40838ab0bf376107ea6dbd65dd450",
        strip_prefix = "envoy-openssl-a8f679ab37d17119b19f6a9eefcb3b0caa8b2c5f",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/a8f679ab37d17119b19f6a9eefcb3b0caa8b2c5f.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
