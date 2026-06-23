
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
        sha256 = "c92d251c87dc46e5660d0dbedf62e6403d61927797882ca8e75daa673c91092d",
        strip_prefix = "envoy-openssl-2729bd9feac0a9e73f4c89eeccddfb23ab09b62f",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/2729bd9feac0a9e73f4c89eeccddfb23ab09b62f.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
