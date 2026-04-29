
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
        sha256 = "76605a6f380807d3e3d5e3318af0ec83b4b02ce5aa25f3077642712dadf3d6be",
        strip_prefix = "envoy-openssl-ec3328bcc4534a9a04e768ee8be866986a83928e",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/ec3328bcc4534a9a04e768ee8be866986a83928e.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
