
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
        sha256 = "af5e78e1b1c0473e70745fee62134d7134875f699fa494e057f9ca322c089ce1",
        strip_prefix = "envoy-openssl-0fcef6c51b6eeff83304ede41d697abd8ba581d2",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/0fcef6c51b6eeff83304ede41d697abd8ba581d2.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
