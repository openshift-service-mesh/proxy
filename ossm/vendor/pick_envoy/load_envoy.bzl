
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
        sha256 = "d245d1d7d6b65d44a662ce9d52fefd75a091d56aa37822638545229f19400a5d",
        strip_prefix = "envoy-openssl-ad678813863651e2eaf169df518acdd148acf6ae",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/ad678813863651e2eaf169df518acdd148acf6ae.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
