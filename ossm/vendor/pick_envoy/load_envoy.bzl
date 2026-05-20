
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
        sha256 = "52b2749caa06cca7374a908e582053276bf3c99ddd5f0518da5f38b05085d595",
        strip_prefix = "envoy-openssl-2fba69e5c5bae21c624224949bcb77ed0ad49f9c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/2fba69e5c5bae21c624224949bcb77ed0ad49f9c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
