globals = struct(
    CcSharedLibraryInfo = None,
    PackageSpecificationInfo = PackageSpecificationInfo,
    RunEnvironmentInfo = RunEnvironmentInfo,
    DefaultInfo = DefaultInfo,
    __TestingOnly_NeverAvailable = None,
    ProtoInfo = getattr(getattr(native, 'legacy_globals', None), 'ProtoInfo', ProtoInfo),
)