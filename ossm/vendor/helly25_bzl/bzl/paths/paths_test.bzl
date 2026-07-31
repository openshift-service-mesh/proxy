# Copyright 2025 The Helly25 Authors.
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

"""Unit tests for paths.bzl."""

load("@bazel_skylib//lib:unittest.bzl", "asserts", "unittest")
load("//bzl/paths:paths.bzl", "paths")

def _assert_eq(env, num, result, expected, msg = None):
    """Asserts that `result` is equal to `expected`."""
    if msg == None:
        msg = "Expected '%s' to equal '%s'" % (result, expected)
    msg += " (assertion #%d)" % num
    asserts.equals(env, expected, result, msg)

def _collapse_test(ctx):
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.collapse("a/./b/./c"), "a/b/c")
    _assert_eq(env, 2, paths.collapse("/./a/b/"), "/a/b")
    _assert_eq(env, 3, paths.collapse("C:\\.\\foo\\.\\bar"), "C:/foo/bar")
    _assert_eq(env, 4, paths.collapse("a/b/../c"), "a/c")

    return unittest.end(env)

def _collapse_windows_test(ctx):
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.collapse_windows("a/./b/./c"), "a\\b\\c")
    _assert_eq(env, 2, paths.collapse_windows("/./a/b/"), "\\a\\b")
    _assert_eq(env, 3, paths.collapse_windows("C:\\.\\foo\\.\\bar"), "C:\\foo\\bar")
    _assert_eq(env, 4, paths.collapse_windows("a/b/../c"), "a\\c")

    return unittest.end(env)

def _ensure_trailing_slash_test(ctx):
    """Unit tests for `paths.ensure_trailing_slash` on Unix."""
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.ensure_trailing_slash(""), "", "Empty stays empty; never promoted to an absolute root")
    _assert_eq(env, 2, paths.ensure_trailing_slash("/"), "/", "Root keeps its single slash")
    _assert_eq(env, 3, paths.ensure_trailing_slash("//"), "/", "Multiple root slashes collapse to one")
    _assert_eq(env, 4, paths.ensure_trailing_slash("///"), "/")
    _assert_eq(env, 5, paths.ensure_trailing_slash("a"), "a/")
    _assert_eq(env, 6, paths.ensure_trailing_slash("a/"), "a/", "Idempotent when already ending in a slash")
    _assert_eq(env, 7, paths.ensure_trailing_slash("a//"), "a/", "Multiple trailing slashes collapse to one")
    _assert_eq(env, 8, paths.ensure_trailing_slash("a/b/c"), "a/b/c/")
    _assert_eq(env, 9, paths.ensure_trailing_slash("/a/b"), "/a/b/")
    _assert_eq(env, 10, paths.ensure_trailing_slash("/a//b///"), "/a/b/", "Cleans interior and trailing slashes")
    _assert_eq(env, 11, paths.ensure_trailing_slash("a/./b"), "a/b/", "Dot segments removed by normalization")
    _assert_eq(env, 12, paths.ensure_trailing_slash("a/b/..", collapse = True), "a/", "Collapsing applies before the separator is added")
    _assert_eq(env, 13, paths.ensure_trailing_slash("", default_if_empty = "/"), "/", "Empty falls back to the requested root")
    _assert_eq(env, 14, paths.ensure_trailing_slash("", default_if_empty = "root"), "root/", "Non-root defaults also get a trailing slash")
    _assert_eq(env, 15, paths.ensure_trailing_slash("//", default_if_empty = "x"), "/", "Default is ignored when the input is non-empty after normalization")
    _assert_eq(env, 16, paths.ensure_trailing_slash("a", default_if_empty = "/"), "a/", "Default is ignored when a real path is present")
    _assert_eq(env, 17, paths.ensure_trailing_slash("", default_if_empty = "."), "", "A default that normalizes away still yields empty")

    return unittest.end(env)

def _ensure_trailing_slash_windows_test(ctx):
    """Unit tests for `paths.ensure_trailing_slash` on Windows."""
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.ensure_trailing_slash_windows(""), "")
    _assert_eq(env, 2, paths.ensure_trailing_slash_windows("/"), "\\", "Single leading slash is the local absolute root")
    _assert_eq(env, 3, paths.ensure_trailing_slash_windows("//"), "\\\\", "UNC root keeps its two slashes, not three")
    _assert_eq(env, 4, paths.ensure_trailing_slash_windows("C:"), "C:\\", "Drive letter gains its root separator")
    _assert_eq(env, 5, paths.ensure_trailing_slash_windows("C:\\"), "C:\\", "Drive root is idempotent")
    _assert_eq(env, 6, paths.ensure_trailing_slash_windows("C:/"), "C:\\")
    _assert_eq(env, 7, paths.ensure_trailing_slash_windows("a"), "a\\")
    _assert_eq(env, 8, paths.ensure_trailing_slash_windows("a\\b\\"), "a\\b\\", "Idempotent when already ending in a backslash")
    _assert_eq(env, 9, paths.ensure_trailing_slash_windows("a/b//"), "a\\b\\", "Mixed and duplicate slashes collapse to one backslash")
    _assert_eq(env, 10, paths.ensure_trailing_slash_windows("C:\\foo\\bar"), "C:\\foo\\bar\\")
    _assert_eq(env, 11, paths.ensure_trailing_slash_windows("//server/share"), "\\\\server\\share\\", "UNC share gains a trailing separator")
    _assert_eq(env, 12, paths.ensure_trailing_slash_windows("//server/share/"), "\\\\server\\share\\", "UNC share idempotent")
    _assert_eq(env, 13, paths.ensure_trailing_slash_windows("", default_if_empty = "/"), "\\", "OS-agnostic '/' default resolves to the Windows local root")
    _assert_eq(env, 14, paths.ensure_trailing_slash_windows("", default_if_empty = "C:"), "C:\\", "Drive-letter default resolves to the drive root")
    _assert_eq(env, 15, paths.ensure_trailing_slash_windows(""), "", "Without a default, empty stays empty")

    return unittest.end(env)

def _is_absolute_test(ctx):
    """Unit tests for paths.is_absolute and paths.is_absolute_windows."""
    env = unittest.begin(ctx)

    # --- Standard POSIX (is_windows = False) ---
    _assert_eq(env, 1, paths.is_absolute(""), False)
    _assert_eq(env, 2, paths.is_absolute("foo/bar"), False)
    _assert_eq(env, 3, paths.is_absolute("../foo"), False)
    _assert_eq(env, 4, paths.is_absolute("/foo/bar"), True, "POSIX absolute path must start with a slash")
    _assert_eq(env, 5, paths.is_absolute("C:/foo"), False, "Drive letters are relative on POSIX")

    return unittest.end(env)

def _is_absolute_windows_test(ctx):
    """Unit tests for paths.is_absolute and paths.is_absolute_windows."""
    env = unittest.begin(ctx)

    _assert_eq(env, 6, paths.is_absolute_windows(""), False)
    _assert_eq(env, 7, paths.is_absolute_windows("foo\\bar"), False)

    # Slashes are recognized cross-platform on Windows
    _assert_eq(env, 8, paths.is_absolute_windows("/foo"), True, "Single leading slash is root-relative absolute")
    _assert_eq(env, 9, paths.is_absolute_windows("\\foo"), True)

    # Windows Drive Letters
    _assert_eq(env, 10, paths.is_absolute_windows("C:"), True, "Drive letters act as roots in our toolchain system")
    _assert_eq(env, 11, paths.is_absolute_windows("D:\\foo"), True)
    _assert_eq(env, 12, paths.is_absolute_windows("z:/foo"), True, "Case-insensitive check for drive letters")

    # UNC Network Paths
    _assert_eq(env, 13, paths.is_absolute_windows("//server/share"), True, "UNC paths are structurally absolute")
    _assert_eq(env, 14, paths.is_absolute_windows("\\\\server\\share"), True)

    return unittest.end(env)

def _join_test(ctx):
    """Unit tests for `paths.join`."""
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.join(""), "")
    _assert_eq(env, 2, paths.join("a"), "a")
    _assert_eq(env, 3, paths.join("/"), "/")
    _assert_eq(env, 4, paths.join("//"), "/")
    _assert_eq(env, 5, paths.join("/a"), "/a")
    _assert_eq(env, 6, paths.join("/a/"), "/a")
    _assert_eq(env, 7, paths.join("/a//"), "/a")

    _assert_eq(env, 8, paths.join("", ""), "")
    _assert_eq(env, 9, paths.join("/", ""), "/")
    _assert_eq(env, 10, paths.join("", "/"), "/")
    _assert_eq(env, 11, paths.join("a", "b"), "a/b")
    _assert_eq(env, 12, paths.join("//a//", "//b//"), "/a/b")
    _assert_eq(env, 13, paths.join("a/b", ""), "a/b")
    _assert_eq(env, 14, paths.join("//a//b//", ""), "/a/b")
    _assert_eq(env, 15, paths.join("//a//b//", "//c//d//"), "/a/b/c/d")

    _assert_eq(env, 16, paths.join("a", "b", "c"), "a/b/c")
    _assert_eq(env, 17, paths.join("/a/", "/b/", "/c/"), "/a/b/c", "Cleanly handles multiple overlapping edge slashes")
    _assert_eq(env, 18, paths.join("a", "", "b", "", "c"), "a/b/c", "Interspersed empty parts are dropped safely across long joins")
    _assert_eq(env, 19, paths.join("/", "a", "b", "c/"), "/a/b/c", "Maintains global root while stripping final trailing slice")
    _assert_eq(env, 20, paths.join("a", ".", "b", "..", "c"), "a/b/../c", "Single dot path segments are cleanly omitted in multi-joins")
    _assert_eq(env, 21, paths.join("a", ".", "b", "..", "c", collapse = True), "a/c", "Single dot path segments are cleanly omitted in multi-joins")
    _assert_eq(env, 22, paths.join("a", "b", "c", collapse = True), "a/b/c")
    _assert_eq(env, 23, paths.join("a", "b", "../c", collapse = True), "a/c", "Collapsing works seamlessly across multi-arg arrays")

    return unittest.end(env)

def _join_windows_test(ctx):
    """Unit tests for `paths.join` on Windows."""
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.join_windows(""), "")
    _assert_eq(env, 2, paths.join_windows("a"), "a")
    _assert_eq(env, 3, paths.join_windows("/"), "\\")
    _assert_eq(env, 4, paths.join_windows("//"), "\\\\")
    _assert_eq(env, 5, paths.join_windows("/a"), "\\a")
    _assert_eq(env, 6, paths.join_windows("/a/"), "\\a")
    _assert_eq(env, 7, paths.join_windows("/a//"), "\\a")

    _assert_eq(env, 8, paths.join_windows("", ""), "")
    _assert_eq(env, 9, paths.join_windows("/", ""), "\\")
    _assert_eq(env, 10, paths.join_windows("", "/"), "\\")
    _assert_eq(env, 11, paths.join_windows("a", "b"), "a\\b")
    _assert_eq(env, 12, paths.join_windows("//a//", "//b//"), "\\\\a\\b")
    _assert_eq(env, 13, paths.join_windows("a\\b", ""), "a\\b")
    _assert_eq(env, 14, paths.join_windows("//a//b//", ""), "\\\\a\\b")
    _assert_eq(env, 15, paths.join_windows("//a//b//", "//c//d//"), "\\\\a\\b\\c\\d")

    _assert_eq(env, 16, paths.join_windows("C:\\foo", "bar"), "C:\\foo\\bar", "Basic drive file append")
    _assert_eq(env, 17, paths.join_windows("C:", "foo"), "C:\\foo", "Maintain drive relative path state if first item has no trailing slash")
    _assert_eq(env, 18, paths.join_windows("C:\\foo", "\\bar"), "C:\\foo\\bar", "Joining a leading-slash element shouldn't obliterate the preceding drive letter root")
    _assert_eq(env, 19, paths.join_windows("a/b", "C:\\foo"), "a\\b\\C:\\foo", "An explicit secondary drive letter should override previous relative paths")

    _assert_eq(env, 20, paths.join_windows("a", "b", "c"), "a\\b\\c")
    _assert_eq(env, 21, paths.join_windows("C:", "a", "b"), "C:\\a\\b", "Drive letter root forces absolute structure across multi-joins")
    _assert_eq(env, 22, paths.join_windows("C:\\", "\\a\\", "\\b\\"), "C:\\a\\b", "Heavy duplicate backslashes are flattened across 3+ parts")
    _assert_eq(env, 23, paths.join_windows("C:\\", "a/./b", "\\c\\"), "C:\\a\\b\\c", "Not dropping the './' segments in multi-joins unless collapsing enabled")
    _assert_eq(env, 24, paths.join_windows("C:\\", "a/./b", "\\c\\", collapse = True), "C:\\a\\b\\c", "Also drop the './' segments cleanly in multi-joins with collapsing enabled")
    _assert_eq(env, 25, paths.join_windows("//server/share", "dir", "file.txt"), "\\\\server\\share\\dir\\file.txt", "UNC root holds perfectly when multiple sub-paths are appended")
    _assert_eq(env, 26, paths.join_windows("a", "b", "..\\c", collapse = True), "a\\c", "Windows multi-arg array collapsing works natively")

    return unittest.end(env)

def _join_respect_absolute_test(ctx):
    """Unit tests for paths.join_respect_absolute."""
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.join_respect_absolute("a", "b", "c"), "a/b/c")
    _assert_eq(env, 2, paths.join_respect_absolute("a/b", "/c/d", "e"), "/c/d/e")
    _assert_eq(env, 3, paths.join_respect_absolute("/a", "/b", "/c"), "/c", "Last absolute path wins completely")
    _assert_eq(env, 4, paths.join_respect_absolute("a\\b", "C:\\foo", "bar"), "a/b/C:/foo/bar")
    _assert_eq(env, 5, paths.join_respect_absolute("C:\\foo", "\\bar"), "/bar", "A single leading slash resets to a drive-relative absolute root")
    _assert_eq(env, 6, paths.join_respect_absolute("a", "b", "//server/share", "c"), "/server/share/c")
    _assert_eq(env, 7, paths.join_respect_absolute("a/b", "/c/d", "../e", collapse = True), "/c/e")

    return unittest.end(env)

def _join_respect_absolute_windows_test(ctx):
    """Unit tests for paths.join_respect_absolute."""
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.join_respect_absolute_windows("a\\b", "C:\\foo", "bar"), "C:\\foo\\bar")
    _assert_eq(env, 2, paths.join_respect_absolute_windows("C:\\foo", "\\bar"), "\\bar", "A single leading slash resets to a drive-relative absolute root")
    _assert_eq(env, 3, paths.join_respect_absolute_windows("a", "b", "//server/share", "c"), "\\\\server\\share\\c")
    _assert_eq(env, 4, paths.join_respect_absolute_windows("a/b", "/c/d", "../e", collapse = True), "\\c\\e")

    return unittest.end(env)

def _normalize_test(ctx):
    """Unit tests for `paths.normalize` on Unix."""
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.normalize(""), "")
    _assert_eq(env, 2, paths.normalize("/"), "/")
    _assert_eq(env, 3, paths.normalize("//"), "/")
    _assert_eq(env, 4, paths.normalize("///"), "/")
    _assert_eq(env, 5, paths.normalize("a/b/c"), "a/b/c")
    _assert_eq(env, 6, paths.normalize("a/./b/../c"), "a/b/../c")
    _assert_eq(env, 7, paths.normalize("/a//b///c/"), "/a/b/c")
    _assert_eq(env, 8, paths.normalize("foo/bar/.."), "foo/bar/..")

    return unittest.end(env)

def _normalize_windows_test(ctx):
    """Unit tests for `paths.normalize` on Windows."""
    env = unittest.begin(ctx)

    _assert_eq(env, 1, paths.normalize_windows(""), "")
    _assert_eq(env, 2, paths.normalize_windows("/"), "\\")
    _assert_eq(env, 3, paths.normalize_windows("\\\\"), "\\\\")
    _assert_eq(env, 4, paths.normalize_windows("C:"), "C:\\", "Drive letters should be treated as absolute roots with a trailing slash")
    _assert_eq(env, 5, paths.normalize_windows("C:/"), "C:\\")
    _assert_eq(env, 6, paths.normalize_windows("C:\\\\a\\\\\\b"), "C:\\a\\b")
    _assert_eq(env, 7, paths.normalize_windows("//server/share"), "\\\\server\\share")
    _assert_eq(env, 8, paths.normalize_windows("\\a\\b\\"), "\\a\\b", "If it starts with one slash, it's a local absolute path on Windows")
    _assert_eq(env, 9, paths.normalize_windows("\\\\server\\share\\"), "\\\\server\\share", "If it starts with two slashes, it's a true UNC path on Windows")
    _assert_eq(env, 10, paths.normalize_windows("C:/foo\\bar/baz\\"), "C:\\foo\\bar\\baz", "Deep mixed slash normalization")
    _assert_eq(env, 11, paths.normalize_windows("\\\\server\\share/dir\\file.txt"), "\\\\server\\share\\dir\\file.txt", "UNC network share string cleanup")
    _assert_eq(env, 12, paths.normalize_windows("C:relative\\path"), "C:\\relative\\path", "Not preserve drive-relative formatting")

    return unittest.end(env)

collapse_test = unittest.make(_collapse_test)
collapse_windows_test = unittest.make(_collapse_windows_test)
ensure_trailing_slash_test = unittest.make(_ensure_trailing_slash_test)
ensure_trailing_slash_windows_test = unittest.make(_ensure_trailing_slash_windows_test)
is_absolute_test = unittest.make(_is_absolute_test)
is_absolute_windows_test = unittest.make(_is_absolute_windows_test)
join_test = unittest.make(_join_test)
join_windows_test = unittest.make(_join_windows_test)
join_respect_absolute_test = unittest.make(_join_respect_absolute_test)
join_respect_absolute_windows_test = unittest.make(_join_respect_absolute_windows_test)
normalize_test = unittest.make(_normalize_test)
normalize_windows_test = unittest.make(_normalize_windows_test)

def paths_test_suite():
    """Creates the test targets and test suite for paths.bzl tests."""
    unittest.suite(
        "paths_tests",
        collapse_test,
        collapse_windows_test,
        ensure_trailing_slash_test,
        ensure_trailing_slash_windows_test,
        is_absolute_test,
        is_absolute_windows_test,
        join_test,
        join_windows_test,
        join_respect_absolute_test,
        join_respect_absolute_windows_test,
        normalize_test,
        normalize_windows_test,
    )
