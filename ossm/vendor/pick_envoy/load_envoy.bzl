
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
        sha256 = "ae294bb0572af89c09ed06648e180ffbc32e8486fd7d12ce03918b3b0e3be691",
        strip_prefix = "envoy-openssl-a302803891072737924a897796531cf9de4eac5c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/a302803891072737924a897796531cf9de4eac5c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
