
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
        sha256 = "6c41f0286b2ef2cfdc938aa9c21b9c0c6222d04c277f0aae5d3a217334223b61",
        strip_prefix = "envoy-openssl-66aac29941eabc313f930bc424d3d9293863f86c",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/66aac29941eabc313f930bc424d3d9293863f86c.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
