
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
        sha256 = "9a1bf183e873500adf6624c9be9f725701e902feed0e29025c4f917524f9ed57",
        strip_prefix = "envoy-openssl-22454ec52174b3c770f4613177f8446d96e2b053",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/22454ec52174b3c770f4613177f8446d96e2b053.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
