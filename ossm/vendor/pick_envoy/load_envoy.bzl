
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
        sha256 = "19331a3311c1b4786696fecb1b222ed06c67a236100d2a467754ed06df47964f",
        strip_prefix = "envoy-openssl-5a271dc4bf59dd0f783d4125aa4e9b39020995cf",
        url = "https://github.com/envoyproxy/envoy-openssl/archive/5a271dc4bf59dd0f783d4125aa4e9b39020995cf.tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@io_istio_proxy//ossm/patches:use-go-from-host.patch",
            "@io_istio_proxy//ossm/patches:use-cmake-from-host.patch",
            ],
    )
