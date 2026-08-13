
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
        sha256 = "d79cf612cd293fef7fd7b85d1ae5bb98ed6d46b48af34dc4f910f51380bfcf61",
        strip_prefix = "envoy-openssl-41ce57abe69da7642c94722d3705ff1152e51eac",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/41ce57abe69da7642c94722d3705ff1152e51eac.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
