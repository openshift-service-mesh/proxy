
config = struct(
  build_python_zip_default = False,
  supports_whl_extraction = True,
  enable_pystar = True,
  enable_deprecation_warnings = False,
  extract_needs_chmod = False,
  bazel_8_or_later = True,
  bazel_9_or_later = False,
  bazel_10_or_later = False,
  BuiltinPyInfo = getattr(getattr(native, "legacy_globals", None), "PyInfo", None),
  BuiltinPyRuntimeInfo = getattr(getattr(native, "legacy_globals", None), "PyRuntimeInfo", None),
  BuiltinPyCcLinkParamsProvider = getattr(getattr(native, "legacy_globals", None), "PyCcLinkParamsProvider", None),
)
