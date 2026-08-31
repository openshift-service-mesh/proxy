bazel_features = struct(
  cc = struct(
    protobuf_on_allowlist = True,
  ),
  proto = struct(
    starlark_proto_info = True,
  ),
  rules = struct(
    analysis_tests_can_transition_on_experimental_incompatible_flags = True,
  ),
  globals = struct(
    PackageSpecificationInfo = PackageSpecificationInfo,
    ProtoInfo = getattr(getattr(native, 'legacy_globals', None), 'ProtoInfo', None),
    cc_proto_aspect = getattr(getattr(native, 'legacy_globals', None), 'cc_proto_aspect', None),
  ),
)
