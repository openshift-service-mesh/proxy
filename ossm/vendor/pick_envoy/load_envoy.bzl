
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
        sha256 = "51ebb87a5c22b1a4d0ee215b58ee043a06af44f6daf141a6d0044835efa069f7",
        strip_prefix = "envoy-openssl-6101f0c75f23e002993684a649b2dae2d5032572",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/6101f0c75f23e002993684a649b2dae2d5032572.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
