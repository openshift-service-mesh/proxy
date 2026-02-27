
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
        sha256 = "aeee3d00c5325a13cdb9c147e48b64225a3a548331fc9cd2001555ec9a04bae3",
        strip_prefix = "envoy-openssl-629675a42b5735c7ea0c3a655ea41f2d65751e54",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/629675a42b5735c7ea0c3a655ea41f2d65751e54.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
