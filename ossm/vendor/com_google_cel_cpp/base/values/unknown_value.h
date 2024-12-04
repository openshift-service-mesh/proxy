// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef THIRD_PARTY_CEL_CPP_BASE_VALUES_UNKNOWN_VALUE_H_
#define THIRD_PARTY_CEL_CPP_BASE_VALUES_UNKNOWN_VALUE_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/optimization.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "base/attribute_set.h"
#include "base/function_result_set.h"
#include "base/handle.h"
#include "base/internal/data.h"
#include "base/internal/unknown_set.h"
#include "base/kind.h"
#include "base/types/unknown_type.h"
#include "base/value.h"
#include "common/any.h"
#include "common/json.h"

namespace cel {

// Representation for unknown results in CEL.
//
// Unknown parts of the environment may be declared at evaluation time. If any
// of the unknown inputs are determined to be required, they are accumulated in
// UnknownValue with set semantics. See Attribute and FunctionResult for
// the representation for unknown values.
class UnknownValue final
    : public Value,
      public base_internal::InlineData,
      public base_internal::EnableHandleFromThis<UnknownValue> {
 public:
  static constexpr ValueKind kKind = ValueKind::kUnknown;

  static bool Is(const Value& value) { return value.kind() == kKind; }

  using Value::Is;

  static const UnknownValue& Cast(const Value& value) {
    ABSL_DCHECK(Is(value)) << "cannot cast " << value.type()->name()
                           << " to unknown";
    return static_cast<const UnknownValue&>(value);
  }

  constexpr ValueKind kind() const { return kKind; }

  const Handle<UnknownType>& type() const { return UnknownType::Get(); }

  std::string DebugString() const;

  absl::StatusOr<Any> ConvertToAny(ValueFactory&) const;

  absl::StatusOr<Json> ConvertToJson(ValueFactory&) const;

  absl::StatusOr<Handle<Value>> ConvertToType(ValueFactory&,
                                              const Handle<Type>&) const;

  absl::StatusOr<Handle<Value>> Equals(ValueFactory& value_factory,
                                       const Value& other) const;

  const AttributeSet& attribute_set() const;

  const FunctionResultSet& function_result_set() const;

 private:
  friend class ValueHandle;
  template <size_t Size, size_t Align>
  friend struct base_internal::AnyData;
  friend struct interop_internal::UnknownValueAccess;

  static constexpr uintptr_t kMetadata =
      base_internal::kStoredInline |
      (static_cast<uintptr_t>(kKind) << base_internal::kKindShift);

  explicit UnknownValue(base_internal::UnknownSet value)
      : base_internal::InlineData(kMetadata), value_(std::move(value)) {}

  explicit UnknownValue(const base_internal::UnknownSet* value_ptr)
      : base_internal::InlineData(kMetadata | base_internal::kTrivial),
        value_ptr_(value_ptr) {}

  UnknownValue(const UnknownValue& other) : UnknownValue(other.value_) {
    // Only called when `other.value_` is the active member.
  }

  UnknownValue(UnknownValue&& other) : UnknownValue(std::move(other.value_)) {
    // Only called when `other.value_` is the active member.
  }

  ~UnknownValue() {
    // Only called when `value_` is the active member.
    value_.~UnknownSet();
  }

  UnknownValue& operator=(const UnknownValue& other) {
    // Only called when `value_` and `other.value_` are the active members.
    if (ABSL_PREDICT_TRUE(this != &other)) {
      value_ = other.value_;
    }
    return *this;
  }

  UnknownValue& operator=(UnknownValue&& other) {
    // Only called when `value_` and `other.value_` are the active members.
    if (ABSL_PREDICT_TRUE(this != &other)) {
      value_ = std::move(other.value_);
    }
    return *this;
  }

  union {
    base_internal::UnknownSet value_;
    const base_internal::UnknownSet* value_ptr_;
  };
};

CEL_INTERNAL_VALUE_DECL(UnknownValue);

namespace base_internal {

template <>
struct ValueTraits<UnknownValue> {
  using type = UnknownValue;

  using type_type = UnknownType;

  using underlying_type = void;

  static std::string DebugString(const type& value) {
    return value.DebugString();
  }

  static Handle<type> Wrap(ValueFactory& value_factory, Handle<type> value) {
    static_cast<void>(value_factory);
    return value;
  }

  static Handle<type> Unwrap(Handle<type> value) { return value; }
};

}  // namespace base_internal

}  // namespace cel

#endif  // THIRD_PARTY_CEL_CPP_BASE_VALUES_UNKNOWN_VALUE_H_
