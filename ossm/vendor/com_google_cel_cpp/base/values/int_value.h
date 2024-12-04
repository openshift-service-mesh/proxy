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

#ifndef THIRD_PARTY_CEL_CPP_BASE_VALUES_INT_VALUE_H_
#define THIRD_PARTY_CEL_CPP_BASE_VALUES_INT_VALUE_H_

#include <cstdint>
#include <string>

#include "absl/base/attributes.h"
#include "absl/base/casts.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "base/handle.h"
#include "base/types/int_type.h"
#include "base/value.h"
#include "common/any.h"
#include "common/json.h"

namespace cel {

class IntValue final : public base_internal::SimpleValue<IntType, int64_t>,
                       public base_internal::EnableHandleFromThis<IntValue> {
 private:
  using Base = base_internal::SimpleValue<IntType, int64_t>;

 public:
  ABSL_ATTRIBUTE_PURE_FUNCTION static std::string DebugString(int64_t value);

  using Base::kKind;

  using Base::Is;

  static const IntValue& Cast(const Value& value) {
    ABSL_DCHECK(Is(value)) << "cannot cast " << value.type()->name()
                           << " to int";
    return static_cast<const IntValue&>(value);
  }

  using Base::kind;

  using Base::type;

  std::string DebugString() const;

  absl::StatusOr<Any> ConvertToAny(ValueFactory&) const;

  absl::StatusOr<Json> ConvertToJson(ValueFactory&) const;

  absl::StatusOr<Handle<Value>> ConvertToType(ValueFactory& value_factory,
                                              const Handle<Type>& type) const;

  absl::StatusOr<Handle<Value>> Equals(ValueFactory& value_factory,
                                       const Value& other) const;

  using Base::NativeValue;

 private:
  using Base::Base;

  CEL_INTERNAL_SIMPLE_VALUE_MEMBERS(IntValue);
};

CEL_INTERNAL_SIMPLE_VALUE_STANDALONES(IntValue);

template <typename H>
H AbslHashValue(H state, const IntValue& value) {
  // Due to heterogeneous lookup, we need to ensure hashing IntValue and
  // UintValue produces the same result when they are heterogeneously equal. We
  // do this by bit casting int64_t to uint64_t here.
  return H::combine(std::move(state),
                    absl::bit_cast<uint64_t>(value.NativeValue()));
}

inline bool operator==(const IntValue& lhs, const IntValue& rhs) {
  return lhs.NativeValue() == rhs.NativeValue();
}

namespace base_internal {

template <>
struct ValueTraits<IntValue> {
  using type = IntValue;

  using type_type = IntType;

  using underlying_type = int64_t;

  static std::string DebugString(underlying_type value) {
    return type::DebugString(value);
  }

  static std::string DebugString(const type& value) {
    return value.DebugString();
  }

  static Handle<type> Wrap(ValueFactory& value_factory, underlying_type value);

  static underlying_type Unwrap(underlying_type value) { return value; }

  static underlying_type Unwrap(const Handle<type>& value) {
    return Unwrap(value->NativeValue());
  }
};

}  // namespace base_internal

}  // namespace cel

#endif  // THIRD_PARTY_CEL_CPP_BASE_VALUES_INT_VALUE_H_
