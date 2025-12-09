
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
        sha256 = "223bcdb7741eecd01c6d5bed86e3e5b449d9fc92f63f9ac70f8c9b4a19d18568",
        strip_prefix = "envoy-openssl-334cbaf17eb53293c7be9671668197b01268f19c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/334cbaf17eb53293c7be9671668197b01268f19c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
