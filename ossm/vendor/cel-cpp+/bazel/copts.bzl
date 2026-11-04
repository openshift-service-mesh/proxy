"""Envoy registry: compiler options applied to all cel-cpp C++ targets."""

CEL_COPTS = select({
    "@platforms//os:windows": [],
    "//conditions:default": [
        # cel-cpp's own .bazelrc builds with -Wno-deprecated-declarations; abseil
        # ABSL_DEPRECATE_AND_INLINE shims used throughout cel-cpp headers otherwise
        # fire in every consuming TU.
        "-Wno-deprecated-declarations",
        # cel-cpp mixes absl::Nonnull/Nullable-annotated and unannotated pointers in the
        # same headers (e.g. common/allocator.h, parser/parser_interface.h); clang then
        # warns on every unannotated pointer in any TU that includes them.
        "-Wno-nullability-completeness",
    ],
})
