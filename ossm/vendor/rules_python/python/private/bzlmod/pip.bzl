# Copyright 2023 The Bazel Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"pip module extension for use with bzlmod"

load("@bazel_features//:features.bzl", "bazel_features")
load("@pythons_hub//:interpreters.bzl", "DEFAULT_PYTHON_VERSION", "INTERPRETER_LABELS")
load(
    "//python/pip_install:pip_repository.bzl",
    "locked_requirements_label",
    "pip_repository_attrs",
    "use_isolated",
    "whl_library",
)
load("//python/pip_install:requirements_parser.bzl", parse_requirements = "parse")
load("//python/private:auth.bzl", "AUTH_ATTRS")
load("//python/private:normalize_name.bzl", "normalize_name")
load("//python/private:parse_whl_name.bzl", "parse_whl_name")
load("//python/private:pypi_index.bzl", "get_simpleapi_sources", "simpleapi_download")
load("//python/private:render_pkg_aliases.bzl", "whl_alias")
load("//python/private:version_label.bzl", "version_label")
load("//python/private:whl_target_platforms.bzl", "select_whl")
load(":pip_repository.bzl", "pip_repository")

def _parse_version(version):
    major, _, version = version.partition(".")
    minor, _, version = version.partition(".")
    patch, _, version = version.partition(".")
    build, _, version = version.partition(".")

    return struct(
        # use semver vocabulary here
        major = major,
        minor = minor,
        patch = patch,  # this is called `micro` in the Python interpreter versioning scheme
        build = build,
    )

def _major_minor_version(version):
    version = _parse_version(version)
    return "{}.{}".format(version.major, version.minor)

def _whl_mods_impl(mctx):
    """Implementation of the pip.whl_mods tag class.

    This creates the JSON files used to modify the creation of different wheels.
"""
    whl_mods_dict = {}
    for mod in mctx.modules:
        for whl_mod_attr in mod.tags.whl_mods:
            if whl_mod_attr.hub_name not in whl_mods_dict.keys():
                whl_mods_dict[whl_mod_attr.hub_name] = {whl_mod_attr.whl_name: whl_mod_attr}
            elif whl_mod_attr.whl_name in whl_mods_dict[whl_mod_attr.hub_name].keys():
                # We cannot have the same wheel name in the same hub, as we
                # will create the same JSON file name.
                fail("""\
Found same whl_name '{}' in the same hub '{}', please use a different hub_name.""".format(
                    whl_mod_attr.whl_name,
                    whl_mod_attr.hub_name,
                ))
            else:
                whl_mods_dict[whl_mod_attr.hub_name][whl_mod_attr.whl_name] = whl_mod_attr

    for hub_name, whl_maps in whl_mods_dict.items():
        whl_mods = {}

        # create a struct that we can pass to the _whl_mods_repo rule
        # to create the different JSON files.
        for whl_name, mods in whl_maps.items():
            build_content = mods.additive_build_content
            if mods.additive_build_content_file != None and mods.additive_build_content != "":
                fail("""\
You cannot use both the additive_build_content and additive_build_content_file arguments at the same time.
""")
            elif mods.additive_build_content_file != None:
                build_content = mctx.read(mods.additive_build_content_file)

            whl_mods[whl_name] = json.encode(struct(
                additive_build_content = build_content,
                copy_files = mods.copy_files,
                copy_executables = mods.copy_executables,
                data = mods.data,
                data_exclude_glob = mods.data_exclude_glob,
                srcs_exclude_glob = mods.srcs_exclude_glob,
            ))

        _whl_mods_repo(
            name = hub_name,
            whl_mods = whl_mods,
        )

def _create_whl_repos(module_ctx, pip_attr, whl_map, whl_overrides, group_map, simpleapi_cache):
    python_interpreter_target = pip_attr.python_interpreter_target

    # if we do not have the python_interpreter set in the attributes
    # we programmatically find it.
    hub_name = pip_attr.hub_name
    if python_interpreter_target == None and not pip_attr.python_interpreter:
        python_name = "python_{}_host".format(
            pip_attr.python_version.replace(".", "_"),
        )
        if python_name not in INTERPRETER_LABELS:
            fail((
                "Unable to find interpreter for pip hub '{hub_name}' for " +
                "python_version={version}: Make sure a corresponding " +
                '`python.toolchain(python_version="{version}")` call exists.' +
                "Expected to find {python_name} among registered versions:\n  {labels}"
            ).format(
                hub_name = hub_name,
                version = pip_attr.python_version,
                python_name = python_name,
                labels = "  \n".join(INTERPRETER_LABELS),
            ))
        python_interpreter_target = INTERPRETER_LABELS[python_name]

    pip_name = "{}_{}".format(
        hub_name,
        version_label(pip_attr.python_version),
    )
    major_minor = _major_minor_version(pip_attr.python_version)

    requirements_lock = locked_requirements_label(module_ctx, pip_attr)

    # Parse the requirements file directly in starlark to get the information
    # needed for the whl_libary declarations below.
    requirements_lock_content = module_ctx.read(requirements_lock)
    parse_result = parse_requirements(requirements_lock_content)

    # Replicate a surprising behavior that WORKSPACE builds allowed:
    # Defining a repo with the same name multiple times, but only the last
    # definition is respected.
    # The requirement lines might have duplicate names because lines for extras
    # are returned as just the base package name. e.g., `foo[bar]` results
    # in an entry like `("foo", "foo[bar] == 1.0 ...")`.
    requirements = {
        normalize_name(entry[0]): entry
        # The WORKSPACE pip_parse sorted entries, so mimic that ordering.
        for entry in sorted(parse_result.requirements)
    }.values()

    extra_pip_args = pip_attr.extra_pip_args + parse_result.options

    if hub_name not in whl_map:
        whl_map[hub_name] = {}

    whl_modifications = {}
    if pip_attr.whl_modifications != None:
        for mod, whl_name in pip_attr.whl_modifications.items():
            whl_modifications[whl_name] = mod

    if pip_attr.experimental_requirement_cycles:
        requirement_cycles = {
            name: [normalize_name(whl_name) for whl_name in whls]
            for name, whls in pip_attr.experimental_requirement_cycles.items()
        }

        whl_group_mapping = {
            whl_name: group_name
            for group_name, group_whls in requirement_cycles.items()
            for whl_name in group_whls
        }

        # TODO @aignas 2024-04-05: how do we support different requirement
        # cycles for different abis/oses? For now we will need the users to
        # assume the same groups across all versions/platforms until we start
        # using an alternative cycle resolution strategy.
        group_map[hub_name] = pip_attr.experimental_requirement_cycles
    else:
        whl_group_mapping = {}
        requirement_cycles = {}

    index_urls = {}
    if pip_attr.experimental_index_url:
        if pip_attr.download_only:
            fail("Currently unsupported to use `download_only` and `experimental_index_url`")

        index_urls = simpleapi_download(
            module_ctx,
            attr = struct(
                index_url = pip_attr.experimental_index_url,
                extra_index_urls = pip_attr.experimental_extra_index_urls or [],
                index_url_overrides = pip_attr.experimental_index_url_overrides or {},
                sources = [requirements_lock_content],
                envsubst = pip_attr.envsubst,
                # Auth related info
                netrc = pip_attr.netrc,
                auth_patterns = pip_attr.auth_patterns,
            ),
            cache = simpleapi_cache,
            parallel_download = pip_attr.parallel_download,
        )

    # Create a new wheel library for each of the different whls
    for whl_name, requirement_line in requirements:
        # We are not using the "sanitized name" because the user
        # would need to guess what name we modified the whl name
        # to.
        annotation = whl_modifications.get(whl_name)
        whl_name = normalize_name(whl_name)

        group_name = whl_group_mapping.get(whl_name)
        group_deps = requirement_cycles.get(group_name, [])

        # Construct args separately so that the lock file can be smaller and does not include unused
        # attrs.
        repo_name = "{}_{}".format(pip_name, whl_name)
        whl_library_args = dict(
            repo = pip_name,
            dep_template = "@{}//{{name}}:{{target}}".format(hub_name),
            requirement = requirement_line,
        )
        maybe_args = dict(
            # The following values are safe to omit if they have false like values
            annotation = annotation,
            download_only = pip_attr.download_only,
            enable_implicit_namespace_pkgs = pip_attr.enable_implicit_namespace_pkgs,
            environment = pip_attr.environment,
            envsubst = pip_attr.envsubst,
            experimental_target_platforms = pip_attr.experimental_target_platforms,
            extra_pip_args = extra_pip_args,
            group_deps = group_deps,
            group_name = group_name,
            pip_data_exclude = pip_attr.pip_data_exclude,
            python_interpreter = pip_attr.python_interpreter,
            python_interpreter_target = python_interpreter_target,
            whl_patches = {
                p: json.encode(args)
                for p, args in whl_overrides.get(whl_name, {}).items()
            },
        )
        whl_library_args.update({k: v for k, v in maybe_args.items() if v})
        maybe_args_with_default = dict(
            # The following values have defaults next to them
            isolated = (use_isolated(module_ctx, pip_attr), True),
            quiet = (pip_attr.quiet, True),
            timeout = (pip_attr.timeout, 600),
        )
        whl_library_args.update({k: v for k, (v, default) in maybe_args_with_default.items() if v == default})

        if index_urls:
            srcs = get_simpleapi_sources(requirement_line)

            whls = []
            sdist = None
            for sha256 in srcs.shas:
                # For now if the artifact is marked as yanked we just ignore it.
                #
                # See https://packaging.python.org/en/latest/specifications/simple-repository-api/#adding-yank-support-to-the-simple-api

                maybe_whl = index_urls[whl_name].whls.get(sha256)
                if maybe_whl and not maybe_whl.yanked:
                    whls.append(maybe_whl)
                    continue

                maybe_sdist = index_urls[whl_name].sdists.get(sha256)
                if maybe_sdist and not maybe_sdist.yanked:
                    sdist = maybe_sdist
                    continue

                print("WARNING: Could not find a whl or an sdist with sha256={}".format(sha256))  # buildifier: disable=print

            distribution = select_whl(
                whls = whls,
                want_abis = [
                    "none",
                    "abi3",
                    "cp" + major_minor.replace(".", ""),
                    # Older python versions have wheels for the `*m` ABI.
                    "cp" + major_minor.replace(".", "") + "m",
                ],
                want_os = module_ctx.os.name,
                want_cpu = module_ctx.os.arch,
            ) or sdist

            if distribution:
                whl_library_args["requirement"] = srcs.requirement
                whl_library_args["urls"] = [distribution.url]
                whl_library_args["sha256"] = distribution.sha256
                whl_library_args["filename"] = distribution.filename
                if pip_attr.netrc:
                    whl_library_args["netrc"] = pip_attr.netrc
                if pip_attr.auth_patterns:
                    whl_library_args["auth_patterns"] = pip_attr.auth_patterns

                # pip is not used to download wheels and the python `whl_library` helpers are only extracting things
                whl_library_args.pop("extra_pip_args", None)

                # This is no-op because pip is not used to download the wheel.
                whl_library_args.pop("download_only", None)
            else:
                print("WARNING: falling back to pip for installing the right file for {}".format(requirement_line))  # buildifier: disable=print

        # We sort so that the lock-file remains the same no matter the order of how the
        # args are manipulated in the code going before.
        whl_library(name = repo_name, **dict(sorted(whl_library_args.items())))
        whl_map[hub_name].setdefault(whl_name, []).append(
            whl_alias(
                repo = repo_name,
                version = major_minor,
                # Call Label() to canonicalize because its used in a different context
                config_setting = Label("//python/config_settings:is_python_" + major_minor),
            ),
        )

def _pip_impl(module_ctx):
    """Implementation of a class tag that creates the pip hub and corresponding pip spoke whl repositories.

    This implementation iterates through all of the `pip.parse` calls and creates
    different pip hub repositories based on the "hub_name".  Each of the
    pip calls create spoke repos that uses a specific Python interpreter.

    In a MODULES.bazel file we have:

    pip.parse(
        hub_name = "pip",
        python_version = 3.9,
        requirements_lock = "//:requirements_lock_3_9.txt",
        requirements_windows = "//:requirements_windows_3_9.txt",
    )
    pip.parse(
        hub_name = "pip",
        python_version = 3.10,
        requirements_lock = "//:requirements_lock_3_10.txt",
        requirements_windows = "//:requirements_windows_3_10.txt",
    )

    For instance, we have a hub with the name of "pip".
    A repository named the following is created. It is actually called last when
    all of the pip spokes are collected.

    - @@rules_python~override~pip~pip

    As shown in the example code above we have the following.
    Two different pip.parse statements exist in MODULE.bazel provide the hub_name "pip".
    These definitions create two different pip spoke repositories that are
    related to the hub "pip".
    One spoke uses Python 3.9 and the other uses Python 3.10. This code automatically
    determines the Python version and the interpreter.
    Both of these pip spokes contain requirements files that includes websocket
    and its dependencies.

    We also need repositories for the wheels that the different pip spokes contain.
    For each Python version a different wheel repository is created. In our example
    each pip spoke had a requirements file that contained websockets. We
    then create two different wheel repositories that are named the following.

    - @@rules_python~override~pip~pip_39_websockets
    - @@rules_python~override~pip~pip_310_websockets

    And if the wheel has any other dependencies subsequent wheels are created in the same fashion.

    The hub repository has aliases for `pkg`, `data`, etc, which have a select that resolves to
    a spoke repository depending on the Python version.

    Also we may have more than one hub as defined in a MODULES.bazel file.  So we could have multiple
    hubs pointing to various different pip spokes.

    Some other business rules notes. A hub can only have one spoke per Python version.  We cannot
    have a hub named "pip" that has two spokes that use the Python 3.9 interpreter.  Second
    we cannot have the same hub name used in sub-modules.  The hub name has to be globally
    unique.

    This implementation also handles the creation of whl_modification JSON files that are used
    during the creation of wheel libraries. These JSON files used via the annotations argument
    when calling wheel_installer.py.

    Args:
        module_ctx: module contents
    """

    # Build all of the wheel modifications if the tag class is called.
    _whl_mods_impl(module_ctx)

    _overriden_whl_set = {}
    whl_overrides = {}

    for module in module_ctx.modules:
        for attr in module.tags.override:
            if not module.is_root:
                fail("overrides are only supported in root modules")

            if not attr.file.endswith(".whl"):
                fail("Only whl overrides are supported at this time")

            whl_name = normalize_name(parse_whl_name(attr.file).distribution)

            if attr.file in _overriden_whl_set:
                fail("Duplicate module overrides for '{}'".format(attr.file))
            _overriden_whl_set[attr.file] = None

            for patch in attr.patches:
                if whl_name not in whl_overrides:
                    whl_overrides[whl_name] = {}

                if patch not in whl_overrides[whl_name]:
                    whl_overrides[whl_name][patch] = struct(
                        patch_strip = attr.patch_strip,
                        whls = [],
                    )

                whl_overrides[whl_name][patch].whls.append(attr.file)

    # Used to track all the different pip hubs and the spoke pip Python
    # versions.
    pip_hub_map = {}

    # Keeps track of all the hub's whl repos across the different versions.
    # dict[hub, dict[whl, dict[version, str pip]]]
    # Where hub, whl, and pip are the repo names
    hub_whl_map = {}
    hub_group_map = {}

    simpleapi_cache = {}

    for mod in module_ctx.modules:
        for pip_attr in mod.tags.parse:
            hub_name = pip_attr.hub_name
            if hub_name not in pip_hub_map:
                pip_hub_map[pip_attr.hub_name] = struct(
                    module_name = mod.name,
                    python_versions = [pip_attr.python_version],
                )
            elif pip_hub_map[hub_name].module_name != mod.name:
                # We cannot have two hubs with the same name in different
                # modules.
                fail((
                    "Duplicate cross-module pip hub named '{hub}': pip hub " +
                    "names must be unique across modules. First defined " +
                    "by module '{first_module}', second attempted by " +
                    "module '{second_module}'"
                ).format(
                    hub = hub_name,
                    first_module = pip_hub_map[hub_name].module_name,
                    second_module = mod.name,
                ))

            elif pip_attr.python_version in pip_hub_map[hub_name].python_versions:
                fail((
                    "Duplicate pip python version '{version}' for hub " +
                    "'{hub}' in module '{module}': the Python versions " +
                    "used for a hub must be unique"
                ).format(
                    hub = hub_name,
                    module = mod.name,
                    version = pip_attr.python_version,
                ))
            else:
                pip_hub_map[pip_attr.hub_name].python_versions.append(pip_attr.python_version)

            _create_whl_repos(module_ctx, pip_attr, hub_whl_map, whl_overrides, hub_group_map, simpleapi_cache)

    for hub_name, whl_map in hub_whl_map.items():
        pip_repository(
            name = hub_name,
            repo_name = hub_name,
            whl_map = {
                key: json.encode(value)
                for key, value in whl_map.items()
            },
            default_version = _major_minor_version(DEFAULT_PYTHON_VERSION),
            groups = hub_group_map.get(hub_name),
        )

def _pip_parse_ext_attrs():
    attrs = dict({
        "experimental_extra_index_urls": attr.string_list(
            doc = """\
The extra index URLs to use for downloading wheels using bazel downloader.
Each value is going to be subject to `envsubst` substitutions if necessary.

The indexes must support Simple API as described here:
https://packaging.python.org/en/latest/specifications/simple-repository-api/

This is equivalent to `--extra-index-urls` `pip` option.
""",
            default = [],
        ),
        "experimental_index_url": attr.string(
            doc = """\
The index URL to use for downloading wheels using bazel downloader. This value is going
to be subject to `envsubst` substitutions if necessary.

The indexes must support Simple API as described here:
https://packaging.python.org/en/latest/specifications/simple-repository-api/

In the future this could be defaulted to `https://pypi.org` when this feature becomes
stable.

This is equivalent to `--index-url` `pip` option.
""",
        ),
        "experimental_index_url_overrides": attr.string_dict(
            doc = """\
The index URL overrides for each package to use for downloading wheels using
bazel downloader. This value is going to be subject to `envsubst` substitutions
if necessary.

The key is the package name (will be normalized before usage) and the value is the
index URL.

This design pattern has been chosen in order to be fully deterministic about which
packages come from which source. We want to avoid issues similar to what happened in
https://pytorch.org/blog/compromised-nightly-dependency/.

The indexes must support Simple API as described here:
https://packaging.python.org/en/latest/specifications/simple-repository-api/
""",
        ),
        "hub_name": attr.string(
            mandatory = True,
            doc = """
The name of the repo pip dependencies will be accessible from.

This name must be unique between modules; unless your module is guaranteed to
always be the root module, it's highly recommended to include your module name
in the hub name. Repo mapping, `use_repo(..., pip="my_modules_pip_deps")`, can
be used for shorter local names within your module.

Within a module, the same `hub_name` can be specified to group different Python
versions of pip dependencies under one repository name. This allows using a
Python version-agnostic name when referring to pip dependencies; the
correct version will be automatically selected.

Typically, a module will only have a single hub of pip dependencies, but this
is not required. Each hub is a separate resolution of pip dependencies. This
means if different programs need different versions of some library, separate
hubs can be created, and each program can use its respective hub's targets.
Targets from different hubs should not be used together.
""",
        ),
        "parallel_download": attr.bool(
            doc = """\
The flag allows to make use of parallel downloading feature in bazel 7.1 and above
when the bazel downloader is used. This is by default enabled as it improves the
performance by a lot, but in case the queries to the simple API are very expensive
or when debugging authentication issues one may want to disable this feature.

NOTE, This will download (potentially duplicate) data for multiple packages if
there is more than one index available, but in general this should be negligible
because the simple API calls are very cheap and the user should not notice any
extra overhead.

If we are in synchronous mode, then we will use the first result that we
find in case extra indexes are specified.
""",
            default = True,
        ),
        "python_version": attr.string(
            mandatory = True,
            doc = """
The Python version the dependencies are targetting, in Major.Minor format
(e.g., "3.11") or patch level granularity (e.g. "3.11.1").

If an interpreter isn't explicitly provided (using `python_interpreter` or
`python_interpreter_target`), then the version specified here must have
a corresponding `python.toolchain()` configured.
""",
        ),
        "whl_modifications": attr.label_keyed_string_dict(
            mandatory = False,
            doc = """\
A dict of labels to wheel names that is typically generated by the whl_modifications.
The labels are JSON config files describing the modifications.
""",
        ),
    }, **pip_repository_attrs)
    attrs.update(AUTH_ATTRS)

    # Like the pip_repository rule, we end up setting this manually so
    # don't allow users to override it.
    attrs.pop("repo_prefix")

    return attrs

def _whl_mod_attrs():
    attrs = {
        "additive_build_content": attr.string(
            doc = "(str, optional): Raw text to add to the generated `BUILD` file of a package.",
        ),
        "additive_build_content_file": attr.label(
            doc = """\
(label, optional): path to a BUILD file to add to the generated
`BUILD` file of a package. You cannot use both additive_build_content and additive_build_content_file
arguments at the same time.""",
        ),
        "copy_executables": attr.string_dict(
            doc = """\
(dict, optional): A mapping of `src` and `out` files for
[@bazel_skylib//rules:copy_file.bzl][cf]. Targets generated here will also be flagged as
executable.""",
        ),
        "copy_files": attr.string_dict(
            doc = """\
(dict, optional): A mapping of `src` and `out` files for
[@bazel_skylib//rules:copy_file.bzl][cf]""",
        ),
        "data": attr.string_list(
            doc = """\
(list, optional): A list of labels to add as `data` dependencies to
the generated `py_library` target.""",
        ),
        "data_exclude_glob": attr.string_list(
            doc = """\
(list, optional): A list of exclude glob patterns to add as `data` to
the generated `py_library` target.""",
        ),
        "hub_name": attr.string(
            doc = """\
Name of the whl modification, hub we use this name to set the modifications for
pip.parse. If you have different pip hubs you can use a different name,
otherwise it is best practice to just use one.

You cannot have the same `hub_name` in different modules.  You can reuse the same
name in the same module for different wheels that you put in the same hub, but you
cannot have a child module that uses the same `hub_name`.
""",
            mandatory = True,
        ),
        "srcs_exclude_glob": attr.string_list(
            doc = """\
(list, optional): A list of labels to add as `srcs` to the generated
`py_library` target.""",
        ),
        "whl_name": attr.string(
            doc = "The whl name that the modifications are used for.",
            mandatory = True,
        ),
    }
    return attrs

# NOTE: the naming of 'override' is taken from the bzlmod native
# 'archive_override', 'git_override' bzlmod functions.
_override_tag = tag_class(
    attrs = {
        "file": attr.string(
            doc = """\
The Python distribution file name which needs to be patched. This will be
applied to all repositories that setup this distribution via the pip.parse tag
class.""",
            mandatory = True,
        ),
        "patch_strip": attr.int(
            default = 0,
            doc = """\
The number of leading path segments to be stripped from the file name in the
patches.""",
        ),
        "patches": attr.label_list(
            doc = """\
A list of patches to apply to the repository *after* 'whl_library' is extracted
and BUILD.bazel file is generated.""",
            mandatory = True,
        ),
    },
    doc = """\
Apply any overrides (e.g. patches) to a given Python distribution defined by
other tags in this extension.""",
)

def _extension_extra_args():
    args = {}

    if bazel_features.external_deps.module_extension_has_os_arch_dependent:
        args = args | {
            "arch_dependent": True,
            "os_dependent": True,
        }

    return args

pip = module_extension(
    doc = """\
This extension is used to make dependencies from pip available.

pip.parse:
To use, call `pip.parse()` and specify `hub_name` and your requirements file.
Dependencies will be downloaded and made available in a repo named after the
`hub_name` argument.

Each `pip.parse()` call configures a particular Python version. Multiple calls
can be made to configure different Python versions, and will be grouped by
the `hub_name` argument. This allows the same logical name, e.g. `@pip//numpy`
to automatically resolve to different, Python version-specific, libraries.

pip.whl_mods:
This tag class is used to help create JSON files to describe modifications to
the BUILD files for wheels.
""",
    implementation = _pip_impl,
    tag_classes = {
        "override": _override_tag,
        "parse": tag_class(
            attrs = _pip_parse_ext_attrs(),
            doc = """\
This tag class is used to create a pip hub and all of the spokes that are part of that hub.
This tag class reuses most of the pip attributes that are found in
@rules_python//python/pip_install:pip_repository.bzl.
The exception is it does not use the arg 'repo_prefix'.  We set the repository
prefix for the user and the alias arg is always True in bzlmod.
""",
        ),
        "whl_mods": tag_class(
            attrs = _whl_mod_attrs(),
            doc = """\
This tag class is used to create JSON file that are used when calling wheel_builder.py.  These
JSON files contain instructions on how to modify a wheel's project.  Each of the attributes
create different modifications based on the type of attribute. Previously to bzlmod these
JSON files where referred to as annotations, and were renamed to whl_modifications in this
extension.
""",
        ),
    },
    **_extension_extra_args()
)

def _whl_mods_repo_impl(rctx):
    rctx.file("BUILD.bazel", "")
    for whl_name, mods in rctx.attr.whl_mods.items():
        rctx.file("{}.json".format(whl_name), mods)

_whl_mods_repo = repository_rule(
    doc = """\
This rule creates json files based on the whl_mods attribute.
""",
    implementation = _whl_mods_repo_impl,
    attrs = {
        "whl_mods": attr.string_dict(
            mandatory = True,
            doc = "JSON endcoded string that is provided to wheel_builder.py",
        ),
    },
)
