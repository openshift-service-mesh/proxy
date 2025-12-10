
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
        sha256 = "7880f8dc6833b91060b5059480ff21b44d7e9d8ddd563ad219d12c0ccb2fa48b",
        strip_prefix = "envoy-openssl-8f8e10efdfd0e5234affaac7c4b93d0a538e70bf",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/8f8e10efdfd0e5234affaac7c4b93d0a538e70bf.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
