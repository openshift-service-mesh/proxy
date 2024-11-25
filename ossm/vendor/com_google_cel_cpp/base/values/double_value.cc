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

#include "base/values/double_value.h"

#include <cmath>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "base/handle.h"
#include "base/kind.h"
#include "base/type.h"
#include "base/value.h"
#include "base/value_factory.h"
#include "base/values/int_value.h"
#include "base/values/uint_value.h"
#include "common/any.h"
#include "common/json.h"
#include "internal/number.h"
#include "internal/serialize.h"
#include "internal/status_macros.h"

namespace cel {

CEL_INTERNAL_VALUE_IMPL(DoubleValue);

namespace {

using internal::SerializeDoubleValue;

std::string DoubleToString(double value) {
  if (std::isfinite(value)) {
    if (std::floor(value) != value) {
      // The double is not representable as a whole number, so use
      // absl::StrCat which will add decimal places.
      return absl::StrCat(value);
    }
    // absl::StrCat historically would represent 0.0 as 0, and we want the
    // decimal places so ZetaSQL correctly assumes the type as double
    // instead of int64_t.
    std::string stringified = absl::StrCat(value);
    if (!absl::StrContains(stringified, '.')) {
      absl::StrAppend(&stringified, ".0");
    } else {
      // absl::StrCat has a decimal now? Use it directly.
    }
    return stringified;
  }
  if (std::isnan(value)) {
    return "nan";
  }
  if (std::signbit(value)) {
    return "-infinity";
  }
  return "+infinity";
}

}  // namespace

std::string DoubleValue::DebugString(double value) {
  return DoubleToString(value);
}

std::string DoubleValue::DebugString() const {
  return DebugString(NativeValue());
}

absl::StatusOr<Any> DoubleValue::ConvertToAny(ValueFactory&) const {
  static constexpr absl::string_view kTypeName = "google.protobuf.DoubleValue";
  absl::Cord data;
  CEL_RETURN_IF_ERROR(SerializeDoubleValue(this->NativeValue(), data));
  return MakeAny(MakeTypeUrl(kTypeName), std::move(data));
}

absl::StatusOr<Json> DoubleValue::ConvertToJson(ValueFactory&) const {
  return NativeValue();
}

absl::StatusOr<Handle<Value>> DoubleValue::ConvertToType(
    ValueFactory& value_factory, const Handle<Type>& type) const {
  switch (type->kind()) {
    case TypeKind::kDouble:
      return handle_from_this();
    case TypeKind::kInt: {
      auto number = internal::Number::FromDouble(NativeValue());
      if (!number.LosslessConvertibleToInt()) {
        return value_factory.CreateErrorValue(
            absl::OutOfRangeError("integer overflow"));
      }
      return value_factory.CreateIntValue(number.AsInt());
    }
    case TypeKind::kUint: {
      auto number = internal::Number::FromDouble(NativeValue());
      if (!number.LosslessConvertibleToUint()) {
        return value_factory.CreateErrorValue(
            absl::OutOfRangeError("unsigned integer overflow"));
      }
      return value_factory.CreateUintValue(number.AsUint());
    }
    case TypeKind::kType:
      return value_factory.CreateTypeValue(this->type());
    case TypeKind::kString:
      return value_factory.CreateStringValue(DoubleToString(NativeValue()));
    default:
      return value_factory.CreateErrorValue(
          base_internal::TypeConversionError(*this->type(), *type));
  }
}

absl::StatusOr<Handle<Value>> DoubleValue::Equals(ValueFactory& value_factory,
                                                  const Value& other) const {
  switch (other.kind()) {
    case ValueKind::kInt:
      return value_factory.CreateBoolValue(
          internal::Number::FromDouble(NativeValue()) ==
          internal::Number::FromInt64(other.As<IntValue>().NativeValue()));
    case ValueKind::kUint:
      return value_factory.CreateBoolValue(
          internal::Number::FromDouble(NativeValue()) ==
          internal::Number::FromUint64(other.As<UintValue>().NativeValue()));
    case ValueKind::kDouble:
      return value_factory.CreateBoolValue(
          internal::Number::FromDouble(NativeValue()) ==
          internal::Number::FromDouble(other.As<DoubleValue>().NativeValue()));
    default:
      return value_factory.CreateBoolValue(false);
  }
}

}  // namespace cel
