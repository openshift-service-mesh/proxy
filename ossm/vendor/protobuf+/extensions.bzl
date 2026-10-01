"""Module extension for configuring protobuf dependency aliases."""

load("//:envoy_deps.bzl", "envoy_module_id", "envoy_pick", "envoy_value")


def _protobuf_deps_repo_impl(repo_ctx):
    repo_ctx.file(
        "BUILD.bazel",
        """alias(
    name = "zlib",
    actual = "{zlib}",
    visibility = ["//visibility:public"],
)
""".format(zlib = str(repo_ctx.attr.zlib)),
    )


_protobuf_deps_repo = repository_rule(
    implementation = _protobuf_deps_repo_impl,
    attrs = {
        "zlib": attr.label(doc = "Label to alias as :zlib."),
    },
)


def _protobuf_impl(module_ctx):
    root = []
    non_root = []
    for mod in module_ctx.modules:
        for tag in mod.tags.deps:
            values = struct(
                module_name = envoy_module_id(mod),
                zlib = envoy_value(tag, "zlib"),
            )
            if mod.is_root:
                root.append(values)
            else:
                non_root.append(values)

    _protobuf_deps_repo(
        name = "protobuf_deps",
        zlib = envoy_pick(
            "protobuf",
            "zlib",
            [(entry.module_name, entry.zlib) for entry in root],
            [(entry.module_name, entry.zlib) for entry in non_root],
            Label("@zlib//:zlib"),
        ),
    )

    return module_ctx.extension_metadata(reproducible = True)


deps = tag_class(
    attrs = {
        "zlib": attr.label(doc = "Optional label to use for protobuf's zlib dependency."),
    },
    doc = "Configures the dependency labels used by protobuf.",
)

protobuf = module_extension(
    implementation = _protobuf_impl,
    tag_classes = {"deps": deps},
    doc = "Creates @protobuf_deps aliases for protobuf's configurable deps.",
)
