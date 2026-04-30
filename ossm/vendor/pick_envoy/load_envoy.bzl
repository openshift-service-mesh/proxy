
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
        sha256 = "17cd1cd145f3775caeb45293a9f357ffa28de3367841b39aaaaf3bb743a6b1be",
        strip_prefix = "envoy-openssl-80b40394a4859782c394e6ab066ae1af2c2f798f",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/80b40394a4859782c394e6ab066ae1af2c2f798f.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
