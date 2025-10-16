
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
        sha256 = "f1fd1dab9a0e54f6d35062f74c08351b4f58c5b7eae368321cfcd360e4a2cb39",
        strip_prefix = "envoy-openssl-c3649c472729d4c995cf96216f312f88a6286b9f",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/c3649c472729d4c995cf96216f312f88a6286b9f.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
