
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
        sha256 = "23a40185710dedfbd19439c7638d6e7b4139b0b83989d74d8ec423e6ad4920b3",
        strip_prefix = "envoy-openssl-14113b3b7593aabd76e7ca30fc5a5d1635900a13",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/14113b3b7593aabd76e7ca30fc5a5d1635900a13.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
