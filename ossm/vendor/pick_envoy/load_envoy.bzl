
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
        sha256 = "b81e9af771a43c9ea1d9a3805c8855b20ea1802489847d5149736e530c941c57",
        strip_prefix = "envoy-openssl-68b4c3634f043815de4fd0d876173c2ca1733b33",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/68b4c3634f043815de4fd0d876173c2ca1733b33.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
