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

#include "base/values/duration_value.h"

#include <string>
#include <utility>

#include "absl/base/optimization.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "base/handle.h"
#include "base/kind.h"
#include "base/type.h"
#include "base/value.h"
#include "base/value_factory.h"
#include "common/any.h"
#include "common/json.h"
#include "internal/serialize.h"
#include "internal/status_macros.h"
#include "internal/time.h"

namespace cel {

CEL_INTERNAL_VALUE_IMPL(DurationValue);

namespace {

using internal::SerializeDuration;

}  // namespace

std::string DurationValue::DebugString(absl::Duration value) {
  return internal::DebugStringDuration(value);
}

std::string DurationValue::DebugString() const {
  return DebugString(NativeValue());
}

absl::StatusOr<Any> DurationValue::ConvertToAny(ValueFactory&) const {
  static constexpr absl::string_view kTypeName = "google.protobuf.Duration";
  auto value = this->NativeValue();
  if (ABSL_PREDICT_FALSE(value == absl::InfiniteDuration() ||
                         value == -absl::InfiniteDuration())) {
    return absl::FailedPreconditionError(
        "infinite duration values cannot be converted to google.protobuf.Any");
  }
  absl::Cord data;
  CEL_RETURN_IF_ERROR(SerializeDuration(value, data));
  return MakeAny(MakeTypeUrl(kTypeName), std::move(data));
}

absl::StatusOr<Json> DurationValue::ConvertToJson(ValueFactory&) const {
  CEL_ASSIGN_OR_RETURN(auto formatted,
                       internal::EncodeDurationToJson(NativeValue()));
  return JsonString(std::move(formatted));
}

absl::StatusOr<Handle<Value>> DurationValue::ConvertToType(
    ValueFactory& value_factory, const Handle<Type>& type) const {
  switch (type->kind()) {
    case TypeKind::kDuration:
      return handle_from_this();
    case TypeKind::kType:
      return value_factory.CreateTypeValue(this->type());
    case TypeKind::kString: {
      auto status_or_string = internal::EncodeDurationToJson(NativeValue());
      if (!status_or_string.ok()) {
        return value_factory.CreateErrorValue(status_or_string.status());
      }
      return value_factory.CreateStringValue(std::move(*status_or_string));
    }
    default:
      return value_factory.CreateErrorValue(
          base_internal::TypeConversionError(*this->type(), *type));
  }
}

absl::StatusOr<Handle<Value>> DurationValue::Equals(ValueFactory& value_factory,
                                                    const Value& other) const {
  return value_factory.CreateBoolValue(
      other.Is<DurationValue>() &&
      NativeValue() == other.As<DurationValue>().NativeValue());
}

}  // namespace cel
