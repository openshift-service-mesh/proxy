
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
        sha256 = "e01da3ba86069226762c4420801f6cde8ac9bf0c809fdefae4fe24f9c7c20cbd",
        strip_prefix = "envoy-openssl-12236bc7c06e522cb26d7d1c4c9648949965a37d",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/12236bc7c06e522cb26d7d1c4c9648949965a37d.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
