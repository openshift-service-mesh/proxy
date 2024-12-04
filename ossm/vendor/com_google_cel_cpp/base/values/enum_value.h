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

#ifndef THIRD_PARTY_CEL_CPP_BASE_VALUES_ENUM_VALUE_H_
#define THIRD_PARTY_CEL_CPP_BASE_VALUES_ENUM_VALUE_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "base/handle.h"
#include "base/internal/data.h"
#include "base/kind.h"
#include "base/type.h"
#include "base/types/enum_type.h"
#include "base/value.h"
#include "common/any.h"
#include "common/json.h"

namespace cel {

class ValueFactory;

// EnumValue represents a single constant belonging to cel::EnumType.
class EnumValue final : public Value,
                        public base_internal::InlineData,
                        public base_internal::EnableHandleFromThis<EnumValue> {
 public:
  static constexpr ValueKind kKind = ValueKind::kEnum;

  static bool Is(const Value& value) { return value.kind() == kKind; }

  using Value::Is;

  static const EnumValue& Cast(const Value& value) {
    ABSL_DCHECK(Is(value)) << "cannot cast " << value.type()->name()
                           << " to enum";
    return static_cast<const EnumValue&>(value);
  }

  static std::string DebugString(const EnumType& type, int64_t value);

  static std::string DebugString(const EnumType& type,
                                 const EnumType::Constant& value);

  using ConstantId = EnumType::ConstantId;

  constexpr ValueKind kind() const { return kKind; }

  const Handle<EnumType>& type() const { return type_; }

  std::string DebugString() const;

  absl::StatusOr<Any> ConvertToAny(ValueFactory&) const;

  absl::StatusOr<Json> ConvertToJson(ValueFactory&) const;

  absl::StatusOr<Handle<Value>> ConvertToType(ValueFactory& value_factory,
                                              const Handle<Type>& type) const;

  absl::StatusOr<Handle<Value>> Equals(ValueFactory& value_factory,
                                       const Value& other) const;

  constexpr int64_t number() const { return number_; }

  absl::string_view name() const;

 private:
  friend class base_internal::ValueHandle;
  template <size_t Size, size_t Align>
  friend struct base_internal::AnyData;

  static constexpr uintptr_t kMetadata =
      base_internal::kStoredInline |
      (static_cast<uintptr_t>(kKind) << base_internal::kKindShift);

  static uintptr_t AdditionalMetadata(const EnumType& type) {
    static_assert(
        std::is_base_of_v<base_internal::InlineData, EnumValue>,
        "This logic relies on the fact that EnumValue is stored inline");
    // Because EnumValue is stored inline and has only two members of which one
    // is int64_t, we can be considered trivial if Handle<EnumType> has a
    // skippable destructor.
    return base_internal::Metadata::IsDestructorSkippable(type)
               ? base_internal::kTrivial
               : uintptr_t{0};
  }

  EnumValue(Handle<EnumType> type, int64_t number)
      : base_internal::InlineData(kMetadata | AdditionalMetadata(*type)),
        type_(std::move(type)),
        number_(number) {}

  Handle<EnumType> type_;
  int64_t number_;
};

CEL_INTERNAL_VALUE_DECL(EnumValue);

namespace base_internal {

template <>
struct ValueTraits<EnumValue> {
  using type = EnumValue;

  using type_type = EnumType;

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

#endif  // THIRD_PARTY_CEL_CPP_BASE_VALUES_ENUM_VALUE_H_
