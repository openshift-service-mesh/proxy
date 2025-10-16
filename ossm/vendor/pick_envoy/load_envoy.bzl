
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
        sha256 = "dec2ba53cdd7a42f799ad7d63119530e5edcac70fede486b9080ae75965dd83b",
        strip_prefix = "envoy-openssl-62d1eeedccd03b31f1c39f82c0a96ee0ac15fdcf",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/62d1eeedccd03b31f1c39f82c0a96ee0ac15fdcf.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
