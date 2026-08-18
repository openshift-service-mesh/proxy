
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
        sha256 = "6012f5651013bae2c849c6dccd0d55f9ec2a2269634b7b083596cf8f9333744a",
        strip_prefix = "envoy-openssl-9f40682e29a465f21aef6227aa0741c40b305309",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/9f40682e29a465f21aef6227aa0741c40b305309.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
