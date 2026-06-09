
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
        sha256 = "43004990fc60931758ab876d061b016ea5c81ca74400430aee57c15e035a2b62",
        strip_prefix = "envoy-openssl-692e6808c11c6fcda626f4ae4bb989e63f684fda",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/692e6808c11c6fcda626f4ae4bb989e63f684fda.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
