
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
        sha256 = "bafd57101610bce1fb05c4946026371e28851e0555a2a7e638254add5c4b19ed",
        strip_prefix = "envoy-openssl-bc44aadbc7d52133b37a3b7db118cbdbd70c446a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/bc44aadbc7d52133b37a3b7db118cbdbd70c446a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
