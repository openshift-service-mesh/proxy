# Copyright 2022 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

"""BUILD rules for Python wrappers."""

load("@pybind11_bazel//:build_defs.bzl", "pybind_extension")
load("@rules_python//python:defs.bzl", "py_binary", "py_library", "py_test")

# Placeholder to use until bazel supports pytype_pybind_extension.
def pytype_pybind_extension(name, **kwargs):
    kwargs.pop("py_deps", None)
    kwargs.pop("pytype_srcs", None)
    pybind_extension(name, **kwargs)

# Placeholder to use until bazel supports pytype_strict_library.
def pytype_strict_library(name, **kwargs):
    py_library(name = name, **kwargs)

# Placeholder to use until bazel supports pytype_strict_binary.
def pytype_strict_binary(name, **kwargs):
    py_binary(name = name, **kwargs)

# Placeholder to use until bazel supports pytype_strict_contrib_test.
def pytype_strict_contrib_test(name, **kwargs):
    py_test(name = name, **kwargs)

# Placeholder to use until bazel supports py_strict_test.
def py_strict_test(name, **kwargs):
    py_test(name = name, **kwargs)
