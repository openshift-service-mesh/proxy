
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
        sha256 = "17bba0402248c905153f37581bb4d1739e900f4a53a8fb7e6b6e1ff322317447",
        strip_prefix = "envoy-openssl-61123e5acd3766288cfd293cb0447a260429fd34",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/61123e5acd3766288cfd293cb0447a260429fd34.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
