
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
        sha256 = "0c73ddc6e17b0d1e87de28905410734f406c27aa9a1ce5c01e4602dbfe4df6db",
        strip_prefix = "envoy-openssl-6658e50309bfc4b030f85eef8b953a81136ff89d",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/6658e50309bfc4b030f85eef8b953a81136ff89d.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
