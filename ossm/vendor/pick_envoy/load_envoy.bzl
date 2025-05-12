
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
        sha256 = "db743527f0b69fbe70fe7bbd023626ddaaa8784cac6e3ef5d294a9a247150571",
        strip_prefix = "envoy-openssl-10a053f09423bbc0674eef6b9ddaf9156300459b",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/10a053f09423bbc0674eef6b9ddaf9156300459b.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
