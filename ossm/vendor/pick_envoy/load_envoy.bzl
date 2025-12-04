
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
        sha256 = "584064c7998ca423044a0342483a75f033b2499ed3dcdc14366c60f7c1c40a07",
        strip_prefix = "envoy-openssl-7bf4aedcb067e410c344d08ddba07231ee9ef778",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7bf4aedcb067e410c344d08ddba07231ee9ef778.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
