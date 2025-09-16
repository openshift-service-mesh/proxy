
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
        sha256 = "39ecf6ae111d2a9109a04b6ea17d14a1650ba43d05d4bac2fe72ce2361773a03",
        strip_prefix = "envoy-openssl-4fff4617f8f95ca466e76013dcf8735c15af4ca8",
        url = "https://github.com/dcillera/envoy-openssl/archive/4fff4617f8f95ca466e76013dcf8735c15af4ca8.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
