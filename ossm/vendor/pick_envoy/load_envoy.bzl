
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
        sha256 = "250ff2c0eb6fb00d91100e519068a6f9c80d293ae492cf8687e220074918fd09",
        strip_prefix = "envoy-openssl-1f4984807a73549a0bf8c7066a421629ad087b61",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/1f4984807a73549a0bf8c7066a421629ad087b61.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
