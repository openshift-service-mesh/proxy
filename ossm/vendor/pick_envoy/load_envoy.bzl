
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
        sha256 = "139440649abf6f0f0696393c9f50a0181b8ac85701022c25fc50f7154b286403",
        strip_prefix = "envoy-openssl-ff2e39893ce5dd71adf715ada35b40fb33eaae53",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/ff2e39893ce5dd71adf715ada35b40fb33eaae53.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
