
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
        sha256 = "7cc2b83b2877346d6a5beba536e3253c66e57102b41524626babea302daa4d86",
        strip_prefix = "envoy-openssl-2ef3e466a8a3b9f3816b3180efc21ba14df17a38",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/2ef3e466a8a3b9f3816b3180efc21ba14df17a38.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
