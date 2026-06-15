
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
        sha256 = "98d08ee5ce2bb79b66944811e6eb69b2de33aec2d9d6a026f8cf823c3ef92fa5",
        strip_prefix = "envoy-openssl-936d99425789ff277144231bc95920efe26c723c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/936d99425789ff277144231bc95920efe26c723c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
