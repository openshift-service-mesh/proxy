
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
        sha256 = "67ed0164741055a007f8ae3ac68ecd579e37d0df2d9facc946be03e12075647d",
        strip_prefix = "envoy-openssl-77b710777b80989d8079f0b87538b7c495fcfccd",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/77b710777b80989d8079f0b87538b7c495fcfccd.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
