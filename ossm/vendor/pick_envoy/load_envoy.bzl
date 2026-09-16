
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
        sha256 = "04bfecb193a2d5741ba0508ee116d223a11f07ffc83ea90720b42c44c0d804df",
        strip_prefix = "envoy-openssl-05ae42b67805fd461a85bde30fad4ce7f461db32",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/05ae42b67805fd461a85bde30fad4ce7f461db32.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
