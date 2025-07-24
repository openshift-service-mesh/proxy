
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
        sha256 = "4826cc21a9bc14738344171605b9b43430ee9e30340708a70d021537a90bc516",
        strip_prefix = "envoy-openssl-7d2cf87be3a4e30dc0ab96172997778b2e5647eb",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/7d2cf87be3a4e30dc0ab96172997778b2e5647eb.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
