
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
        sha256 = "1bf1b0a021f3579bc87e3b1a1f3764a84cdeaaa0194571b3a109ca008d792165",
        strip_prefix = "envoy-openssl-31f52a136b9b64ef004953b04ebea16a73c72bc3",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/31f52a136b9b64ef004953b04ebea16a73c72bc3.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
