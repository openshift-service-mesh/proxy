"""Module extension for configuring libsxg dependency aliases."""

load("//:envoy_deps.bzl", "envoy_module_id", "envoy_pick", "envoy_value")


def _libsxg_deps_repo_impl(repo_ctx):
    repo_ctx.file(
        "BUILD.bazel",
        """alias(
    name = "crypto_lib",
    actual = "{crypto_lib}",
    visibility = ["//visibility:public"],
)
""".format(crypto_lib = str(repo_ctx.attr.crypto_lib)),
    )


_libsxg_deps_repo = repository_rule(
    implementation = _libsxg_deps_repo_impl,
    attrs = {
        "crypto_lib": attr.string(doc = "Label to alias as :crypto_lib."),
    },
)


def _libsxg_impl(module_ctx):
    root = []
    non_root = []
    for mod in module_ctx.modules:
        for tag in mod.tags.deps:
            values = struct(
                module_name = envoy_module_id(mod),
                crypto_lib = envoy_value(tag, "crypto_lib"),
            )
            if mod.is_root:
                root.append(values)
            else:
                non_root.append(values)

    _libsxg_deps_repo(
        name = "libsxg_deps",
        crypto_lib = str(envoy_pick(
            "libsxg",
            "crypto_lib",
            [(entry.module_name, entry.crypto_lib) for entry in root],
            [(entry.module_name, entry.crypto_lib) for entry in non_root],
            "@boringssl//:crypto",
        )),
    )

    return module_ctx.extension_metadata(reproducible = True)


deps = tag_class(
    attrs = {
        "crypto_lib": attr.label(doc = "Optional label to use for libsxg's crypto dependency."),
    },
    doc = "Configures the dependency labels used by libsxg.",
)

libsxg = module_extension(
    implementation = _libsxg_impl,
    tag_classes = {"deps": deps},
    doc = "Creates @libsxg_deps aliases for libsxg's configurable deps.",
)
