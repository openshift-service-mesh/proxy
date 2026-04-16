
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
        sha256 = "7a117cec175cf13cb77f67aed1229c4fe709a45a579f35a4ea1cf2997c123e9c",
        strip_prefix = "envoy-openssl-7f9fb90617c1bccdfc9f28ca07a533bccb494b53",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7f9fb90617c1bccdfc9f28ca07a533bccb494b53.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
