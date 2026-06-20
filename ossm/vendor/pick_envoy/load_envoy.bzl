
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
        sha256 = "c9016ba3ee2b711e1fdb1fc98506b6c73dbe98f25e7072622b78c2ba9b9b0fc3",
        strip_prefix = "envoy-openssl-0b4b21fd873260f2f1897df44d8fd60e305fb84a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/0b4b21fd873260f2f1897df44d8fd60e305fb84a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
