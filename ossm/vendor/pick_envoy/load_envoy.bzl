
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
        sha256 = "196bbccbab0f1165dbd386296efaeb7f073fbb7d233adfd9a88c241eecc64923",
        strip_prefix = "envoy-openssl-7e9bada4b3979adb7118ba09e8996ce2d8980a4c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7e9bada4b3979adb7118ba09e8996ce2d8980a4c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
