
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
        sha256 = "93c74d96cb2bd4055afbaab9855209b8c7b53b4c8ab2fd012616f7b2b4a41d3f",
        strip_prefix = "envoy-openssl-96743c1ac67a76152b69dae937c04cec7a426360",
        url = "https://github.com/jwendell/envoy-openssl/archive/96743c1ac67a76152b69dae937c04cec7a426360.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
