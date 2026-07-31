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

"""A starlark implementation of path manipulationfunctions.

SEE [README.md](https://github.com/helly25/bzl/blob/main/README.md).
"""

def _collapse(path, is_windows = False):
    """Lexically collapses '..' segments from a normalized path string.

    WARNING: This is a purely structural string manipulation helper. It does NOT inspect the actual
    file system, meaning it is NOT symlink-safe. It will blindly collapse 'foo/bar/..' into 'foo'
    even if 'bar' is a symlink.

    Args:
        path: The input path string to collapse.
        is_windows: If True, applies Windows-specific rules (e.g. drive letters and UNC paths).
    Returns:
        A path string with '..' segments collapsed as possible, without inspecting the file system.
    """
    if not path:
        return ""

    separator = "\\" if is_windows else "/"
    normalized = path.replace("\\", "/")

    # 1. Parse out the prefix to protect boundaries
    prefix = ""
    if is_windows:
        if len(normalized) >= 2 and normalized[1] == ":":
            # Windows Drive Letter (e.g., "C:") -> Enforce absolute root structure
            prefix = normalized[:2] + "/"
            normalized = normalized[2:]
        elif normalized.startswith("//"):
            prefix = "//"
            normalized = normalized[2:]
        elif normalized.startswith("/"):
            prefix = "/"
            normalized = normalized[1:]
    elif normalized.startswith("/"):
        prefix = "/"
        normalized = normalized[1:]

    # 2. Process segments lexically (dropping '..' if a parent exists)
    segments = [seg for seg in normalized.split("/") if seg]
    collapsed = []

    for seg in segments:
        if seg == ".":
            continue
        if seg == "..":
            if collapsed and collapsed[-1] != "..":
                collapsed.pop()
            elif prefix:
                # Root or drive letter boundary reached; ignore further upward traversal
                continue
            else:
                # Relative path traversing upward past its start point (e.g., "../../a")
                collapsed.append(seg)
        else:
            collapsed.append(seg)

    # 3. Rebuild the final path
    final_path = prefix + "/".join(collapsed)
    final_path = final_path.replace("/", separator)

    if not final_path and prefix:
        return prefix.replace("/", separator)

    return final_path

def _is_absolute(path, is_windows = False):
    """Returns True if the given path is structurally absolute."""
    if not path:
        return False

    # Standardize for processing
    normalized = path.replace("\\", "/")

    if is_windows:
        if len(normalized) >= 2 and normalized[1] == ":":
            return True
        if normalized.startswith("/"):
            return True
    elif normalized.startswith("/"):
        return True

    return False

def _normalize(path, collapse = False, is_windows = False):
    """Normalizes a path by removing redundant separators and standardizing slashes.

    NOTE: On Windows: This function deliberately treats all drive letters (e.g. 'C:') as absolute
    path roots. It does NOT support Windows 'drive-relative' paths (e.g. 'C:foo'). If a drive letter
    is detected without a trailing slash, a separator will be injected (e.g., 'C:foo' -> 'C:\\foo')
    to ensure deterministic execution within Bazel toolchain actions.

    Args:
        path: The input path string to normalize.
        collapse: If True, applies '..' segment collapsing to the final normalized path.
        is_windows: If True, applies Windows-specific normalization (e.g. drive letters, UNC paths).
    Returns:
        A normalized path string with redundant separators removed and consistent slashes.
    """
    if not path:
        return ""

    # Convert all backslashes to forward slashes for internal processing
    normalized = path.replace("\\", "/")

    # 1. Extract Windows specific prefixes (Drive letters or UNC paths)
    prefix = ""
    if is_windows:
        if len(normalized) >= 2 and normalized[1] == ":":
            # Windows Drive Letter (e.g., "C:") -> Enforce absolute root structure
            prefix = normalized[:2] + "/"
            normalized = normalized[2:]
        elif normalized.startswith("//"):
            # True UNC / Network path (starts with two slashes)
            prefix = "//"
            normalized = normalized[2:]
        elif normalized.startswith("/"):
            # Single leading slash is a normal absolute path root on Windows
            prefix = "/"
            normalized = normalized[1:]
    elif normalized.startswith("/"):
        prefix = "/"

    # 2. Clean up the remaining path segments (removes empty, double, or trailing slashes)
    segments = [seg for seg in normalized.split("/") if seg and seg != "."]
    cleaned_path = prefix + "/".join(segments)

    # 3. Convert to the final target OS separator
    separator = "\\" if is_windows else "/"
    final_path = cleaned_path.replace("/", separator)

    # Edge case: If the input was just "/" or "\\" and stripped down to empty, restore the root
    if not final_path and prefix:
        return prefix.replace("/", separator)

    if collapse:
        final_path = _collapse(final_path, is_windows = is_windows)

    return final_path

def _ensure_trailing_slash(path, collapse = False, default_if_empty = "", is_windows = False):
    """Ensures the path ends with exactly one trailing separator, after normalization.

    The path is first normalized (redundant and trailing separators removed, slashes
    standardized), then a single trailing separator is appended -- unless the path is empty or is
    a root that already carries its own separator.

    Edge cases:
        * An empty input falls back to `default_if_empty` (default ""). With the default, the
          result stays "" -- returning a bare separator would wrongly promote a relative path to an
          absolute one. Pass `default_if_empty = "/"` to instead anchor empty input at the root.
        * Roots keep their single separator and are never doubled (e.g. "/" -> "/", "C:" -> "C:\\",
          and the UNC root "//" -> "\\\\").
        * One or more existing trailing separators collapse to exactly one (e.g. "a//" -> "a/").

    Args:
        path: The input path string.
        collapse: If True, applies '..' segment collapsing during normalization.
        default_if_empty: Path to fall back to when `path` normalizes to empty. It is itself
            normalized and given a trailing separator, so a single OS-agnostic "/" yields the
            correct root per platform ("/" on Unix, "\\" on Windows) without hard-coding a
            separator at the call site. The default "" preserves the empty result.
        is_windows: If True, applies Windows-specific normalization and uses '\\' as the separator.
    Returns:
        The normalized path ending in a single separator, or "" when both `path` and
        `default_if_empty` normalize to empty.
    """
    normalized = _normalize(path, collapse = collapse, is_windows = is_windows)
    if not normalized:
        # Fall back to the caller-provided default, processed identically so its OS-specific root
        # form is derived rather than assumed (e.g. "/" -> "\\" on Windows).
        normalized = _normalize(default_if_empty, collapse = collapse, is_windows = is_windows)
    if not normalized:
        return ""

    separator = "\\" if is_windows else "/"

    # Roots (e.g. "/", "C:\\", the UNC root "\\\\") already end in their separator; don't double it.
    if normalized.endswith(separator):
        return normalized

    return normalized + separator

def _join(*parts, collapse = False, is_windows = False):
    """Joins path parts by stitching them together with a separator, then normalizes.

    NOTE: On Windows: If a drive letter (e.g., 'C:') is encountered  as the FIRST non-empty segment,
    it is treated as an absolute path root. If a drive letter appears in a SUBSEQUENT segment, it
    will be treated as a literal directory name and appended sequentially (e.g., joining 'a/b' with
    'C:\\foo' yields 'a\\b\\C:\\foo').

    This avoids silent path-truncation bugs common in standard OS path utilities.

    Args:
        *parts: A variable number of path segments to join.
        collapse: If True, applies '..' segment collapsing to the final joined path.
        is_windows: If True, applies Windows-specific joining and normalization rules.
    Returns:
        A single normalized path string resulting from joining the input parts.
    """
    separator = "\\" if is_windows else "/"

    # Filter out empty strings/None, then join roughly before full normalization
    raw_joined = separator.join([p for p in parts if p])
    return _normalize(raw_joined, collapse = collapse, is_windows = is_windows)

def _join_respect_absolute(*parts, collapse = False, is_windows = False):
    """Joins path parts, but resets the root if an absolute path is encountered."""

    # Traverse backwards to find the last absolute path segment
    start_index = 0
    for i in range(len(parts) - 1, -1, -1):
        if _is_absolute(parts[i], is_windows = is_windows):
            start_index = i
            break

    # Slice the parts from the last absolute path onward
    valid_parts = parts[start_index:]

    # Delegate the actual stitching and normalization to our existing _join function
    return _join(collapse = collapse, is_windows = is_windows, *valid_parts)

def _forward_kwargs(kwargs, **overrides):
    """Creates a forwarded dictionary by merging kwargs with forced overrides.

    Any key present in the `overrides` dictionary will be automatically removed
    from `kwargs` first to prevent duplicate parameter evaluation errors in Starlark.
    """
    filtered = dict(kwargs)
    for key in overrides:
        filtered.pop(key, None)
    filtered.update(overrides)
    return filtered

paths = struct(
    collapse = _collapse,
    collapse_windows = lambda path: _collapse(path, is_windows = True),
    ensure_trailing_slash = _ensure_trailing_slash,
    ensure_trailing_slash_windows = lambda path, **kwargs: _ensure_trailing_slash(path, **_forward_kwargs(kwargs, is_windows = True)),
    is_absolute = _is_absolute,
    is_absolute_windows = lambda path: _is_absolute(path, is_windows = True),
    join = _join,
    join_windows = lambda *parts, **kwargs: _join(*parts, **_forward_kwargs(kwargs, is_windows = True)),
    join_respect_absolute = _join_respect_absolute,
    join_respect_absolute_windows = lambda *parts, **kwargs: _join_respect_absolute(*parts, **_forward_kwargs(kwargs, is_windows = True)),
    normalize = _normalize,
    normalize_windows = lambda path, **kwargs: _normalize(path, **_forward_kwargs(kwargs, is_windows = True)),
)
