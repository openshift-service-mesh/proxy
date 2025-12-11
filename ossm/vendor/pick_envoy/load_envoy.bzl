
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
        sha256 = "cb17881d85a5ce2f60aa536483ebd8db9877d7231dafecbdfdb73853dd795b78",
        strip_prefix = "envoy-openssl-0eb44650048f0ac1aae75fdc29358065fae1445c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/0eb44650048f0ac1aae75fdc29358065fae1445c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
