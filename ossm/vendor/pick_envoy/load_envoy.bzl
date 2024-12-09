
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
        sha256 = "322144a5e548cf0959ab2917dfe6e54f2efb87cd75a466569f4efd7058537e32",
        strip_prefix = "envoy-openssl-de293d89aeedf9f9f85f9a40a3d9f8ea2de385d0",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/de293d89aeedf9f9f85f9a40a3d9f8ea2de385d0.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
