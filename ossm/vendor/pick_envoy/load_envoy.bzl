
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
        sha256 = "795eb7066ec71b77f13bb7cb15bc5342c70fee866fa07b126f64972683a15567",
        strip_prefix = "envoy-openssl-06260f8fdd46ec948c21497963f59c3da6bbb385",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/06260f8fdd46ec948c21497963f59c3da6bbb385.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
