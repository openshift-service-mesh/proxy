
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
        sha256 = "87b795e9182811c26169821b34818fff8be9b27e4eb3486694ed30a25cbf365a",
        strip_prefix = "envoy-openssl-2c1479f1fd12f2ed2d330357467ef535ae6c58c2",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/2c1479f1fd12f2ed2d330357467ef535ae6c58c2.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
