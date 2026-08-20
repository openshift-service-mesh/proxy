
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
        sha256 = "9eea2dc6c9f2bcd175630b2a5bcb1c32888ce28b5a1af0bcddf7872bab0fbb55",
        strip_prefix = "envoy-openssl-ed710d490463600c18d6f065b6d4e33efc4ad420",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/ed710d490463600c18d6f065b6d4e33efc4ad420.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
