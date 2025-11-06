
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
        sha256 = "f7dc4d38626fa157d35ce659e8b81205b55fb133adb68b776e6c96ba2bd5b78c",
        strip_prefix = "envoy-openssl-8962073aa4019e8bc7a1e3e9ade4cd5d48be0169",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/8962073aa4019e8bc7a1e3e9ade4cd5d48be0169.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
