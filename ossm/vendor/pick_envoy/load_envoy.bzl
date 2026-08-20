
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
        sha256 = "78303a61b61c2d1d5bbd71721f995525b2eefd94d0fe2037594b588d6148f840",
        strip_prefix = "envoy-openssl-f5bb6462099b3857f9495b8ca0db594eaa58740c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/f5bb6462099b3857f9495b8ca0db594eaa58740c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
