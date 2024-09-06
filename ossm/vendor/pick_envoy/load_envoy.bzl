
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
        sha256 = "88b6be3623e500aff1065f039a22e531ae519f141743989ff0afd271299e0225",
        strip_prefix = "envoy-openssl-d4d677ddca38c5d3bff3dddcd0237d6f05f673a0",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/d4d677ddca38c5d3bff3dddcd0237d6f05f673a0.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
