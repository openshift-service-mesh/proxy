
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
        sha256 = "fac4e5566ed23130e260932d8d66baa330a826d6364a37bf9a458c45615017a4",
        strip_prefix = "envoy-openssl-1feda79b726583d2e2ecbd9a8c0f0e1268979827",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/1feda79b726583d2e2ecbd9a8c0f0e1268979827.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
