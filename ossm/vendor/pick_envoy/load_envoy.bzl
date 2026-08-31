
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
        sha256 = "113ace8396d8ccf1eb415436643e4faa7cebbd6f001f78a7d724eea6fe9d92f1",
        strip_prefix = "envoy-openssl-1db6f313130a1fb21c9f44b28af297c33b7f6f5a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/1db6f313130a1fb21c9f44b28af297c33b7f6f5a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
