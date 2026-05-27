
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
        sha256 = "a2eab2e63b42cf16963433dbcb05e40e93b2899cd64fb3c9fba645d970330eea",
        strip_prefix = "envoy-openssl-9629fd26a2252bab3a761e1d50ecf65176ab9094",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/9629fd26a2252bab3a761e1d50ecf65176ab9094.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
