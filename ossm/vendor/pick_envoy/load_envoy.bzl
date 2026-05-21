
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
        sha256 = "5d091399089c3711af2d8a57042a53b8143ac943ae9efc0c510909553d5264e2",
        strip_prefix = "envoy-openssl-530bb01275e3d5910977eba036a4d4923132329e",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/530bb01275e3d5910977eba036a4d4923132329e.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
