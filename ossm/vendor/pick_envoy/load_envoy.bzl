
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
        sha256 = "2cf23281d3401e2d0241b0296042d3424dc6a757c8c17778afa477e4d60b8e32",
        strip_prefix = "envoy-openssl-eeacbb6644f1dc9517721b7a2c9794b95e4804b2",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/eeacbb6644f1dc9517721b7a2c9794b95e4804b2.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
