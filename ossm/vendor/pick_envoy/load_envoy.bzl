
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
        sha256 = "848646638642ea7c4ea60d37dbedee5273f6ef8f2e611fa21e55dbbca44154b6",
        strip_prefix = "envoy-openssl-c8d86b31aaaff40aaee0fd512fc6fa409484866a",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/c8d86b31aaaff40aaee0fd512fc6fa409484866a.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
