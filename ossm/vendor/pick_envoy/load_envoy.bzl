
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
        sha256 = "96f9f9ed68511b09035cc6862ce24b933c2b859d6435929021bd9fc409d99512",
        strip_prefix = "envoy-openssl-cac4dcf7e16a936568c1728958e8bc712777643e",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/cac4dcf7e16a936568c1728958e8bc712777643e.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
