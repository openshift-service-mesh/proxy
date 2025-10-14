
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
        sha256 = "27431e3d45f82c9b3dfa72b0bb75c00a2a30e54f17b4dedf9825da560ad7106b",
        strip_prefix = "envoy-openssl-f644146c6d58ecfb3753cf0f1d2c20c639b3d609",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/f644146c6d58ecfb3753cf0f1d2c20c639b3d609.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
