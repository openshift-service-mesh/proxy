
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
        sha256 = "a6aa4b1918932a350ba5fed1aed07b51da3a26d46386a7e49e2075c3a006aa0b",
        strip_prefix = "envoy-openssl-4426155a2bcf9de69a17f51090515fb3750c7569",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/4426155a2bcf9de69a17f51090515fb3750c7569.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
