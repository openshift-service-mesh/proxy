"""Module extension for configuring grpc dependency aliases."""

load("//:envoy_deps.bzl", "envoy_module_id", "envoy_pick", "envoy_value")


def _grpc_deps_repo_impl(repo_ctx):
    repo_ctx.file(
        "BUILD.bazel",
        """alias(
    name = "crypto",
    actual = "{crypto}",
    visibility = ["//visibility:public"],
)

alias(
    name = "ssl",
    actual = "{ssl}",
    visibility = ["//visibility:public"],
)

alias(
    name = "zlib",
    actual = "{zlib}",
    visibility = ["//visibility:public"],
)
""".format(
            crypto = str(repo_ctx.attr.crypto),
            ssl = str(repo_ctx.attr.ssl),
            zlib = str(repo_ctx.attr.zlib),
        ),
    )


_grpc_deps_repo = repository_rule(
    implementation = _grpc_deps_repo_impl,
    attrs = {
        "crypto": attr.label(doc = "Label to alias as :crypto."),
        "ssl": attr.label(doc = "Label to alias as :ssl."),
        "zlib": attr.label(doc = "Label to alias as :zlib."),
    },
)


def _grpc_impl(module_ctx):
    root = []
    non_root = []
    for mod in module_ctx.modules:
        for tag in mod.tags.deps:
            values = struct(
                module_name = envoy_module_id(mod),
                crypto = envoy_value(tag, "crypto"),
                ssl = envoy_value(tag, "ssl"),
                zlib = envoy_value(tag, "zlib"),
            )
            if mod.is_root:
                root.append(values)
            else:
                non_root.append(values)

    _grpc_deps_repo(
        name = "grpc_deps",
        crypto = envoy_pick(
            "grpc",
            "crypto",
            [(entry.module_name, entry.crypto) for entry in root],
            [(entry.module_name, entry.crypto) for entry in non_root],
            Label("@boringssl//:crypto"),
        ),
        ssl = envoy_pick(
            "grpc",
            "ssl",
            [(entry.module_name, entry.ssl) for entry in root],
            [(entry.module_name, entry.ssl) for entry in non_root],
            Label("@boringssl//:ssl"),
        ),
        zlib = envoy_pick(
            "grpc",
            "zlib",
            [(entry.module_name, entry.zlib) for entry in root],
            [(entry.module_name, entry.zlib) for entry in non_root],
            Label("@zlib//:zlib"),
        ),
    )

    return module_ctx.extension_metadata(reproducible = True)


deps = tag_class(
    attrs = {
        "crypto": attr.label(doc = "Optional label to use for grpc's crypto dependency."),
        "ssl": attr.label(doc = "Optional label to use for grpc's TLS/SSL dependency."),
        "zlib": attr.label(doc = "Optional label to use for grpc's zlib dependency."),
    },
    doc = "Configures the dependency labels used by grpc.",
)

grpc = module_extension(
    implementation = _grpc_impl,
    tag_classes = {"deps": deps},
    doc = "Creates @grpc_deps aliases for grpc's configurable deps.",
)
