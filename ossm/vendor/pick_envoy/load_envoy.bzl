
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
        sha256 = "ef47ae1070c4733aab2c05c877361a7771890587bffd23495ca978bfacce2a4c",
        strip_prefix = "envoy-openssl-cf94891c4cec311290bee71ce3232ea2fbd418f6",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/cf94891c4cec311290bee71ce3232ea2fbd418f6.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
