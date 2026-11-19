"""Module extension for configuring proxy-wasm-cpp-host dependency aliases."""

load("//:envoy_deps.bzl", "envoy_module_id", "envoy_pick", "envoy_value")


def _proxy_wasm_cpp_host_deps_repo_impl(repo_ctx):
    repo_ctx.file(
        "BUILD.bazel",
        """alias(
    name = "crypto_lib",
    actual = "{crypto_lib}",
    visibility = ["//visibility:public"],
)

alias(
    name = "wamr_lib",
    actual = "{wamr_lib}",
    visibility = ["//visibility:public"],
)

alias(
    name = "wasmtime_lib",
    actual = "{wasmtime_lib}",
    visibility = ["//visibility:public"],
)

alias(
    name = "prefixed_wasmtime_lib",
    actual = "{prefixed_wasmtime_lib}",
    visibility = ["//visibility:public"],
)

alias(
    name = "wasmedge_lib",
    actual = "{wasmedge_lib}",
    visibility = ["//visibility:public"],
)

alias(
    name = "v8_engine",
    actual = "{v8_engine}",
    visibility = ["//visibility:public"],
)
""".format(
            crypto_lib = str(repo_ctx.attr.crypto_lib),
            wamr_lib = str(repo_ctx.attr.wamr_lib),
            wasmtime_lib = str(repo_ctx.attr.wasmtime_lib),
            prefixed_wasmtime_lib = str(repo_ctx.attr.prefixed_wasmtime_lib),
            wasmedge_lib = str(repo_ctx.attr.wasmedge_lib),
            v8_engine = str(repo_ctx.attr.v8_engine),
        ),
    )


_proxy_wasm_cpp_host_deps_repo = repository_rule(
    implementation = _proxy_wasm_cpp_host_deps_repo_impl,
    attrs = {
        "crypto_lib": attr.string(doc = "Label to alias as :crypto_lib."),
        "wamr_lib": attr.string(doc = "Label to alias as :wamr_lib."),
        "wasmtime_lib": attr.string(doc = "Label to alias as :wasmtime_lib."),
        "prefixed_wasmtime_lib": attr.string(doc = "Label to alias as :prefixed_wasmtime_lib."),
        "wasmedge_lib": attr.string(doc = "Label to alias as :wasmedge_lib."),
        "v8_engine": attr.string(doc = "Label to alias as :v8_engine."),
    },
)


def _proxy_wasm_cpp_host_impl(module_ctx):
    root = []
    non_root = []
    for mod in module_ctx.modules:
        for tag in mod.tags.deps:
            values = struct(
                module_name = envoy_module_id(mod),
                crypto_lib = envoy_value(tag, "crypto_lib"),
                wamr_lib = envoy_value(tag, "wamr_lib"),
                wasmtime_lib = envoy_value(tag, "wasmtime_lib"),
                prefixed_wasmtime_lib = envoy_value(tag, "prefixed_wasmtime_lib"),
                wasmedge_lib = envoy_value(tag, "wasmedge_lib"),
                v8_engine = envoy_value(tag, "v8_engine"),
            )
            if mod.is_root:
                root.append(values)
            else:
                non_root.append(values)

    _proxy_wasm_cpp_host_deps_repo(
        name = "proxy_wasm_cpp_host_deps",
        crypto_lib = str(envoy_pick(
            "proxy_wasm_cpp_host",
            "crypto_lib",
            [(entry.module_name, entry.crypto_lib) for entry in root],
            [(entry.module_name, entry.crypto_lib) for entry in non_root],
            "@boringssl//:crypto",
        )),
        wamr_lib = str(envoy_pick(
            "proxy_wasm_cpp_host",
            "wamr_lib",
            [(entry.module_name, entry.wamr_lib) for entry in root],
            [(entry.module_name, entry.wamr_lib) for entry in non_root],
            "@com_github_bytecodealliance_wasm_micro_runtime//:wamr_lib",
        )),
        wasmtime_lib = str(envoy_pick(
            "proxy_wasm_cpp_host",
            "wasmtime_lib",
            [(entry.module_name, entry.wasmtime_lib) for entry in root],
            [(entry.module_name, entry.wasmtime_lib) for entry in non_root],
            "@com_github_wasmtime//:wasmtime_lib",
        )),
        prefixed_wasmtime_lib = str(envoy_pick(
            "proxy_wasm_cpp_host",
            "prefixed_wasmtime_lib",
            [(entry.module_name, entry.prefixed_wasmtime_lib) for entry in root],
            [(entry.module_name, entry.prefixed_wasmtime_lib) for entry in non_root],
            "@com_github_wasmtime//:prefixed_wasmtime_lib",
        )),
        wasmedge_lib = str(envoy_pick(
            "proxy_wasm_cpp_host",
            "wasmedge_lib",
            [(entry.module_name, entry.wasmedge_lib) for entry in root],
            [(entry.module_name, entry.wasmedge_lib) for entry in non_root],
            "@@proxy-wasm-cpp-host+//bazel:default_wasmedge_lib",
        )),
        v8_engine = str(envoy_pick(
            "proxy_wasm_cpp_host",
            "v8_engine",
            [(entry.module_name, entry.v8_engine) for entry in root],
            [(entry.module_name, entry.v8_engine) for entry in non_root],
            "@@proxy-wasm-cpp-host+//bazel:wee8_no_pointer_compression",
        )),
    )

    return module_ctx.extension_metadata(reproducible = True)


deps = tag_class(
    attrs = {
        "crypto_lib": attr.label(doc = "Optional label to use for proxy-wasm-cpp-host's crypto dependency."),
        "wamr_lib": attr.label(doc = "Optional label to use for proxy-wasm-cpp-host's WAMR dependency."),
        "wasmtime_lib": attr.label(doc = "Optional label to use for proxy-wasm-cpp-host's Wasmtime dependency."),
        "prefixed_wasmtime_lib": attr.label(doc = "Optional label to use for proxy-wasm-cpp-host's prefixed Wasmtime dependency."),
        "wasmedge_lib": attr.label(doc = "Optional label to use for proxy-wasm-cpp-host's WasmEdge dependency."),
        "v8_engine": attr.label(doc = "Optional label to use for proxy-wasm-cpp-host's V8 dependency."),
    },
    doc = "Configures the dependency labels used by proxy-wasm-cpp-host.",
)

proxy_wasm_cpp_host = module_extension(
    implementation = _proxy_wasm_cpp_host_impl,
    tag_classes = {"deps": deps},
    doc = "Creates @proxy_wasm_cpp_host_deps aliases for proxy-wasm-cpp-host's configurable deps.",
)
