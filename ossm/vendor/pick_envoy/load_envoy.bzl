
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
        sha256 = "ed9a79dfe643bce204ee9816b5576fbbebc89df93d23a344ea021937494ac47e",
        strip_prefix = "envoy-openssl-6b87b3cb1e14398db7aa42f185ddee8f0065fbc9",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/6b87b3cb1e14398db7aa42f185ddee8f0065fbc9.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
