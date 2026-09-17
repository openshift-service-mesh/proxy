load(":constants.bzl", "FLAVOR_VERSION", "RULE_TO_FLAVOR")

def _imports_impl(repo_ctx):
    loads = [
        """load("{}", "make_fail_macro")""".format(Label(":fail_macro.bzl")),
    ]
    assignments = []

    for name, file in repo_ctx.attr.rules.items():
        if file:
            loads.append("""load("{file}", _{name} = "{name}")""".format(
                file = file,
                name = name,
            ))
            assignments.append("""{name} = _{name}""".format(
                name = name,
            ))
        else:
            flavor = RULE_TO_FLAVOR[name]
            if flavor:
                message = """Add 'bazel_dep(name = "googleapis-{flavor}", version = "{flavor_version}")' to your MODULE.bazel file to use '{name}' targets in 'googleapis'.""".format(
                    flavor = flavor,
                    flavor_version = FLAVOR_VERSION,
                    name = name,
                )
            else:
                message = """'{name} targets in googleapis are not supported with Bzlmod. If you need them, please file an issue at https://github.com/bazelbuild/bazel-central-registry.""".format(
                    name = name,
                )
            assignments.append("""{name} = make_fail_macro({message})""".format(
                name = name,
                message = repr(message),
            ))
    imports_content = "\n".join(loads + assignments)

    repo_ctx.file("BUILD.bazel")
    repo_ctx.file("imports.bzl", imports_content)

_imports = repository_rule(
    implementation = _imports_impl,
    attrs = {
        # Maps a name to a file label in unambiguous form.
        "rules": attr.string_dict(),
    },
)

# This hack is needed due to direct references to @io_bazel_rules_go//proto:go_grpc in build files.
# Create an alias repo that resembles rules_go and forwards the go_grpc target to the actual target.
def _io_bazel_rules_go_grpc_forwarder_impl(repo_ctx):
    content = ""
    if repo_ctx.attr.go_grpc_label:
        content = """\
alias(
    name = "go_grpc",
    actual = "{go_grpc_label}",
    visibility = ["//visibility:public"],
)
""".format(go_grpc_label = repo_ctx.attr.go_grpc_label)
    else:
        content = """fail("Please add `bazel_dep(name = "googleapis-go", version = "{flavor_version}")' to your MODULE.bazel file to use 'go_proto_library' targets in 'googleapis'.")""".format(
            flavor_version = FLAVOR_VERSION,
        )
    repo_ctx.file("proto/BUILD.bazel", content)

_io_bazel_rules_go_grpc_forwarder = repository_rule(
    implementation = _io_bazel_rules_go_grpc_forwarder_impl,
    attrs = {
        "go_grpc_label": attr.string(),
    }
)

def _rules_registry_impl(module_ctx):
    rules = {name: "" for name in RULE_TO_FLAVOR.keys()}

    for module in module_ctx.modules:
        if module.name != "googleapis" and not module.name.startswith("googleapis-"):
            fail("This extension is internal to googleapis and cannot be accessed from " + module.name)
        for rule in module.tags.register:
            if rule.name not in rules:
                fail("Unknown rule: %s" % rule.name)
            if rules[rule.name]:
                fail("Rule %s already registered" % rule.name)
            rules[rule.name] = str(rule.file)

    _imports(
        name = "com_google_googleapis_imports",
        rules = rules,
    )

    go_grpc_label = ""
    go_proto_library_file = rules.get("go_proto_library")
    if go_proto_library_file:
        go_grpc_label = "@@{}//proto:go_grpc".format(Label(go_proto_library_file).workspace_name)
    _io_bazel_rules_go_grpc_forwarder(
        name = "io_bazel_rules_go",
        go_grpc_label = go_grpc_label,
    )

    return module_ctx.extension_metadata(reproducible = True)

_register = tag_class(
    doc = "Registers a .bzl file defining a rule that googleapis can load.",
    attrs = {
        "name": attr.string(
            doc = "The name of the rule."
        ),
        "file": attr.label(
            doc = "The label of the .bzl file defining the rule.",
        ),
    },
)

rules_registry = module_extension(
    implementation = _rules_registry_impl,
    tag_classes = {
        "register": _register,
    },
)
