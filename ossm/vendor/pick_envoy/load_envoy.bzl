
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
        sha256 = "e47d9605a9bdc509a2dd5ff1daccfc52ad101f60fe25ebbba675d914075e150f",
        strip_prefix = "envoy-openssl-b6d3289779c0e7f3e3edace669ce361164dae6cb",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/b6d3289779c0e7f3e3edace669ce361164dae6cb.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
