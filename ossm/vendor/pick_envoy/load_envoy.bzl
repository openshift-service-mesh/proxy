
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
        sha256 = "da51fd7fa23009c61d4eadc74778c79c2dc23b6b3c4ccd2004d010731c962019",
        strip_prefix = "envoy-openssl-03c0f52121d52cc63558070ae3e39a5f3dca2f29",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/03c0f52121d52cc63558070ae3e39a5f3dca2f29.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
