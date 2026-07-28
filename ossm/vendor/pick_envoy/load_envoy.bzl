
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
        sha256 = "61fec5307fa2946d1d17a5364642780239551b7632dc7095e744ddfbd0447bfd",
        strip_prefix = "envoy-openssl-584080e78b43a3308c4dbc5a1d6c2cbdc570ebb7",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/584080e78b43a3308c4dbc5a1d6c2cbdc570ebb7.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
