
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
        sha256 = "9a638ff1d2fcc44d8079b39fdb6c76ea108bb498fcb86c7500631fcf6e07f174",
        strip_prefix = "envoy-openssl-e2ffc8690134bc6f959221d30928c1ad468090e2",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/e2ffc8690134bc6f959221d30928c1ad468090e2.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
