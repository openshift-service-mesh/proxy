
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
        sha256 = "0043b94b79d6c25905a954c18f7d5a23f36334f5d4e77b5fa3de97dea6f0ca6a",
        strip_prefix = "envoy-openssl-7d41abaf6e733c5678b9b7a01a27f93364b8df52",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7d41abaf6e733c5678b9b7a01a27f93364b8df52.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
