"""Module extension for configuring quiche dependency aliases."""

load("//:envoy_deps.bzl", "envoy_module_id", "envoy_pick")

_DEPS = [
    struct(name = "zlib", default = Label("@zlib//:z"), testonly = False),
    struct(name = "ssl_lib", default = Label("@boringssl//:ssl"), testonly = False),
    struct(name = "quic_base_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "quiche_export_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "quiche_flags_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "quiche_logging_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "quiche_lower_case_string_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "quiche_platform_iovec_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "quiche_stack_trace_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "quiche_time_utils_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "mobile_quiche_bug_tracker_impl_lib", default = Label("//:empty_impl"), testonly = False),
    struct(name = "quiche_expect_bug_impl_lib", default = Label("//:empty_impl"), testonly = True),
    struct(name = "quiche_test_helpers_impl_lib", default = Label("//:empty_impl"), testonly = True),
    struct(name = "quiche_test_impl_lib", default = Label("//:empty_impl"), testonly = True),
    struct(name = "quiche_test_output_impl_lib", default = Label("//:empty_impl"), testonly = True),
    struct(name = "quiche_thread_impl_lib", default = Label("//:empty_impl"), testonly = True),
]


def _deps_attrs(doc):
    attrs = {}
    for dep in _DEPS:
        attrs[dep.name] = attr.label(doc = doc % dep.name)
    return attrs


def _alias_build(dep, actual):
    lines = [
        "alias(",
        '    name = "{name}",'.format(name = dep.name),
        '    actual = "{actual}",'.format(actual = actual),
        '    visibility = ["//visibility:public"],',
    ]
    if dep.testonly:
        lines.append("    testonly = True,")
    lines.append(")")
    return "\n".join(lines)


def _quiche_deps_repo_impl(repo_ctx):
    aliases = [_alias_build(dep, str(getattr(repo_ctx.attr, dep.name))) for dep in _DEPS]
    repo_ctx.file("BUILD.bazel", "\n\n".join(aliases) + "\n")


_quiche_deps_repo = repository_rule(
    implementation = _quiche_deps_repo_impl,
    attrs = _deps_attrs("Label to alias as :%s."),
)


def _quiche_impl(module_ctx):
    root = []
    non_root = []
    for mod in module_ctx.modules:
        for tag in mod.tags.deps:
            values = {"module_name": envoy_module_id(mod)}
            for dep in _DEPS:
                values[dep.name] = getattr(tag, dep.name)
            if mod.is_root:
                root.append(values)
            else:
                non_root.append(values)

    picked = {}
    for dep in _DEPS:
        picked[dep.name] = envoy_pick(
            "quiche",
            dep.name,
            [(entry["module_name"], entry[dep.name]) for entry in root],
            [(entry["module_name"], entry[dep.name]) for entry in non_root],
            dep.default,
        )

    _quiche_deps_repo(
        name = "quiche_deps",
        **picked
    )

    return module_ctx.extension_metadata(reproducible = True)


deps = tag_class(
    attrs = _deps_attrs("Optional label to use for quiche's %s dependency."),
    doc = "Configures the dependency labels used by quiche.",
)

quiche = module_extension(
    implementation = _quiche_impl,
    tag_classes = {"deps": deps},
    doc = "Creates @quiche_deps aliases for quiche's configurable deps.",
)
