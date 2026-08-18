
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
        sha256 = "4c97f991889fd5e9d4553be1fbb08628a2d3d90b360d89ec1cdb1ff7bf461ea5",
        strip_prefix = "envoy-openssl-6b4e316dc51c5e6676fdb48abe5dc8422657edbc",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/6b4e316dc51c5e6676fdb48abe5dc8422657edbc.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
