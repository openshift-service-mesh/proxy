
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
        sha256 = "7772dcebb478b0d000c4b03a767c451d9fb629a0fc71ce7714ce0e423cc1a92f",
        strip_prefix = "envoy-fa21ad4b3e69db0b1fef628a18964e7d26af5b31",
        url = "https://github.com/envoyproxy/envoy/archive/fa21ad4b3e69db0b1fef628a18964e7d26af5b31.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            "@io_istio_proxy//ossm/patches:fix-python3-genrule.patch",
            "@io_istio_proxy//ossm/patches:add-luajit2-build-setting.patch",
            "@io_istio_proxy//ossm/patches:add-luajit2-target.patch",
            ],
    )
