
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
        sha256 = "4f8983a4e83cf28e6ddfe03aef902f69a9ff438eb57d8d1a713a0f8fbb1979e3",
        strip_prefix = "envoy-openssl-8efa1ca0ce366eaaee1c9c7e97903b819cb13982",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/8efa1ca0ce366eaaee1c9c7e97903b819cb13982.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
