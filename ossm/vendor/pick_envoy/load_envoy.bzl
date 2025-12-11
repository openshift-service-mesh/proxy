
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
        sha256 = "bf5ff05ce884ba8f4f7550dc8d630650e3addf4704030ada54a9d9d01f87d777",
        strip_prefix = "envoy-openssl-2f89cd32151a4478b978419104fbbb5c8f02901e",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/2f89cd32151a4478b978419104fbbb5c8f02901e.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
