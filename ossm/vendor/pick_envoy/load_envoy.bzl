
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
        sha256 = "8a424ac3302230f790f23a37857fbe8651640636353c516cb9914946a236d093",
        strip_prefix = "envoy-openssl-ad523c1105c7a01b2ec5c56840085a4664154b8c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/ad523c1105c7a01b2ec5c56840085a4664154b8c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
