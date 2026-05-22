
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
        sha256 = "11024d7f5691d79f1eac6afd6777a5fdb8400023afb90449b181bf893bd69770",
        strip_prefix = "envoy-openssl-c81944318e776282bd53c8ff0dfd4e601330628e",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/c81944318e776282bd53c8ff0dfd4e601330628e.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
