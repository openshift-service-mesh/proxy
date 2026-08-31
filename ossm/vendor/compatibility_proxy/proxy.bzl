
load("@rules_java//java/bazel/rules:bazel_java_binary_wrapper.bzl", _java_binary = "java_binary")
load("@rules_java//java/bazel/rules:bazel_java_import.bzl", _java_import = "java_import")
load("@rules_java//java/bazel/rules:bazel_java_library.bzl", _java_library = "java_library")
load("@rules_java//java/bazel/rules:bazel_java_plugin.bzl", _java_plugin = "java_plugin")
load("@rules_java//java/bazel/rules:bazel_java_test.bzl", _java_test = "java_test")
load("@rules_java//java/bazel:http_jar.bzl", _http_jar = "http_jar")
load("@rules_java//java/common/rules:java_package_configuration.bzl", _java_package_configuration = "java_package_configuration")
load("@rules_java//java/common/rules:java_runtime.bzl", _java_runtime = "java_runtime")
load("@rules_java//java/common/rules:java_toolchain.bzl", _java_toolchain = "java_toolchain")
load("@rules_java//java/private:java_common.bzl", _java_common = "java_common")
load("@rules_java//java/private:java_common_internal.bzl", _java_common_internal_compile = "compile")
load("@rules_java//java/private:java_info.bzl", _JavaInfo = "JavaInfo", _JavaPluginInfo = "JavaPluginInfo",
  _java_info_internal_merge = "merge", _java_info_to_implicit_exportable = "to_implicit_exportable")

java_binary = _java_binary
java_import = _java_import
java_library = _java_library
java_plugin = _java_plugin
java_test = _java_test
java_package_configuration = _java_package_configuration
java_runtime = _java_runtime
java_toolchain = _java_toolchain
java_common = _java_common
JavaInfo = _JavaInfo
JavaPluginInfo = _JavaPluginInfo
java_common_internal_compile = _java_common_internal_compile
java_info_internal_merge = _java_info_internal_merge
java_info_to_implicit_exportable = _java_info_to_implicit_exportable
http_jar = _http_jar
            