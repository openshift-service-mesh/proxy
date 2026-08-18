
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
        sha256 = "d423bc1ab09e0974c72246c2d33970b5be9eab3bd2c48729051b022b25e95496",
        strip_prefix = "envoy-openssl-0d390124872679c4fcdbd418e6a278542662e0f6",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/0d390124872679c4fcdbd418e6a278542662e0f6.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
