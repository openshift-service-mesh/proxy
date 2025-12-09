
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
        sha256 = "bd614ebfc8b7d58b441e630c7c916759c89e8d03ceef05cf8768588b287060b0",
        strip_prefix = "envoy-openssl-f80c2fe327667512878876a9a664c7527d664f59",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/f80c2fe327667512878876a9a664c7527d664f59.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
