
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
        sha256 = "685e4c7e2e5515b766748ecda8fc90e85c4c537a64dbe8b4ca69b6890172f841",
        strip_prefix = "envoy-openssl-afc67ae0a0e1b318d0e8c78f849cd635328cc5d4",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/afc67ae0a0e1b318d0e8c78f849cd635328cc5d4.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
