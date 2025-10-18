
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
        sha256 = "34ca73ec362745e9e6031e00c38e481f60f1e2f9765d39b7b26ab2fb1601d4b0",
        strip_prefix = "envoy-openssl-526cf9129f8d94b96faa8976a1b493d81b53896d",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/526cf9129f8d94b96faa8976a1b493d81b53896d.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
