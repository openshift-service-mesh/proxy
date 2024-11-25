#ifndef THIRD_PARTY_CEL_CPP_EVAL_EVAL_UNKNOWNS_UTILITY_H_
#define THIRD_PARTY_CEL_CPP_EVAL_EVAL_UNKNOWNS_UTILITY_H_

#include "absl/types/span.h"
#include "base/attribute_set.h"
#include "base/function_descriptor.h"
#include "base/function_result_set.h"
#include "base/handle.h"
#include "base/value.h"
#include "base/value_factory.h"
#include "eval/eval/attribute_trail.h"

namespace google::api::expr::runtime {

// Helper class for handling unknowns and missing attribute logic. Provides
// helpers for merging unknown sets from arguments on the stack and for
// identifying unknown/missing attributes based on the patterns for a given
// Evaluation.
// Neither moveable nor copyable.
class AttributeUtility {
 public:
  AttributeUtility(
      absl::Span<const cel::AttributePattern> unknown_patterns,
      absl::Span<const cel::AttributePattern> missing_attribute_patterns,
      cel::ValueFactory& value_factory)
      : unknown_patterns_(unknown_patterns),
        missing_attribute_patterns_(missing_attribute_patterns),
        value_factory_(value_factory) {}

  AttributeUtility(const AttributeUtility&) = delete;
  AttributeUtility& operator=(const AttributeUtility&) = delete;
  AttributeUtility(AttributeUtility&&) = delete;
  AttributeUtility& operator=(AttributeUtility&&) = delete;

  // Checks whether particular corresponds to any patterns that define missing
  // attribute.
  bool CheckForMissingAttribute(const AttributeTrail& trail) const;

  // Checks whether particular corresponds to any patterns that define unknowns.
  bool CheckForUnknown(const AttributeTrail& trail, bool use_partial) const;

  // Creates merged UnknownAttributeSet.
  // Scans over the args collection, determines if there matches to unknown
  // patterns and returns the (possibly empty) collection.
  cel::AttributeSet CheckForUnknowns(absl::Span<const AttributeTrail> args,
                                     bool use_partial) const;

  // Creates merged UnknownValue.
  // Scans over the args collection, merges any UnknownValues found.
  // Returns the merged UnknownValue or nullopt if not found.
  absl::optional<cel::Handle<cel::UnknownValue>> MergeUnknowns(
      absl::Span<const cel::Handle<cel::Value>> args) const;

  // Creates merged UnknownValue.
  // Merges together UnknownValues found in the args
  // along with attributes from attr that match the configured unknown patterns
  // Returns returns the merged UnknownValue if available or nullopt.
  absl::optional<cel::Handle<cel::UnknownValue>> IdentifyAndMergeUnknowns(
      absl::Span<const cel::Handle<cel::Value>> args,
      absl::Span<const AttributeTrail> attrs, bool use_partial) const;

  // Create an initial UnknownSet from a single attribute.
  cel::Handle<cel::UnknownValue> CreateUnknownSet(cel::Attribute attr) const;

  // Factory function for missing attribute errors.
  absl::StatusOr<cel::Handle<cel::ErrorValue>> CreateMissingAttributeError(
      const cel::Attribute& attr) const;

  // Create an initial UnknownSet from a single missing function call.
  cel::Handle<cel::UnknownValue> CreateUnknownSet(
      const cel::FunctionDescriptor& fn_descriptor, int64_t expr_id,
      absl::Span<const cel::Handle<cel::Value>> args) const;

 private:
  absl::Span<const cel::AttributePattern> unknown_patterns_;
  absl::Span<const cel::AttributePattern> missing_attribute_patterns_;
  cel::ValueFactory& value_factory_;
};

}  // namespace google::api::expr::runtime

#endif  // THIRD_PARTY_CEL_CPP_EVAL_EVAL_UNKNOWNS_UTILITY_H_
