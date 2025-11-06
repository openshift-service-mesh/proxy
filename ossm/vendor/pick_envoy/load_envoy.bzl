
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
        sha256 = "4192527fcbdd6dcf93104307a5d4b7d196a796c71af19023bd249bb7358e4ecd",
        strip_prefix = "envoy-openssl-2d5b0813e49e8e189e12e2e87d108bf1de540644",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/2d5b0813e49e8e189e12e2e87d108bf1de540644.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
