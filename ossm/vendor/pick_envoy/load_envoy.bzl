
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
        sha256 = "f001ce2ee221a8b58d036890755b9c7ec9950bb8401bdaafbe358e2bdf0bd4ad",
        strip_prefix = "envoy-openssl-9b3454174151b612f52518dc9df274dc9aeca0db",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/9b3454174151b612f52518dc9df274dc9aeca0db.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
