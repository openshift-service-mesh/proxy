
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
        sha256 = "f8dc7071ac98eed7820894c0ecfc3edf234a9079d28a32e9029ab6de49ae3266",
        strip_prefix = "envoy-openssl-1ebd9285440de40b4ca620f84a21775d8e63a134",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/1ebd9285440de40b4ca620f84a21775d8e63a134.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
