
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
        sha256 = "8095506e6163d283c2fa282b9f8306aa41bed29ef2ea861145714d5ff86b5e94",
        strip_prefix = "envoy-openssl-6ae7dfda12aa49e63feba5f7b50b2fd670965e7d",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/6ae7dfda12aa49e63feba5f7b50b2fd670965e7d.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
