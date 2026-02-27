
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
        sha256 = "2abeacda93f713f86ddead1d68f3511a31f74debe4fbbe7acd25f26f89159c55",
        strip_prefix = "envoy-openssl-e2cdb78bdb3eb27222385dc731465c6997a65516",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/e2cdb78bdb3eb27222385dc731465c6997a65516.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
