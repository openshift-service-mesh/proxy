
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
        sha256 = "5dcfea234aaf4080f549a9a91641b40c19729eac174fc06b3436d55bd35401ee",
        strip_prefix = "envoy-openssl-69ca00550f97f1beab088446f55970eae1940551",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/69ca00550f97f1beab088446f55970eae1940551.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
