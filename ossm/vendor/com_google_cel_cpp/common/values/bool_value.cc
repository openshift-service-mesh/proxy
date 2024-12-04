// Copyright 2023 Google LLC
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

#include <cstddef>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "common/any.h"
#include "common/json.h"
#include "common/value.h"
#include "internal/serialize.h"
#include "internal/status_macros.h"

namespace cel {

namespace {

std::string BoolDebugString(bool value) { return value ? "true" : "false"; }

}  // namespace

std::string BoolValue::DebugString() const {
  return BoolDebugString(NativeValue());
}

absl::StatusOr<Json> BoolValue::ConvertToJson() const { return NativeValue(); }

std::string BoolValueView::DebugString() const {
  return BoolDebugString(NativeValue());
}

absl::StatusOr<size_t> BoolValue::GetSerializedSize() const {
  return internal::SerializedBoolValueSize(NativeValue());
}

absl::Status BoolValue::SerializeTo(absl::Cord& value) const {
  return internal::SerializeBoolValue(NativeValue(), value);
}

absl::StatusOr<absl::Cord> BoolValue::Serialize() const {
  absl::Cord value;
  CEL_RETURN_IF_ERROR(SerializeTo(value));
  return value;
}

absl::StatusOr<std::string> BoolValue::GetTypeUrl(
    absl::string_view prefix) const {
  return MakeTypeUrlWithPrefix(prefix, "google.protobuf.BoolValue");
}

absl::StatusOr<Any> BoolValue::ConvertToAny(absl::string_view prefix) const {
  CEL_ASSIGN_OR_RETURN(auto value, Serialize());
  CEL_ASSIGN_OR_RETURN(auto type_url, GetTypeUrl(prefix));
  return MakeAny(std::move(type_url), std::move(value));
}

absl::StatusOr<size_t> BoolValueView::GetSerializedSize() const {
  return internal::SerializedBoolValueSize(NativeValue());
}

absl::Status BoolValueView::SerializeTo(absl::Cord& value) const {
  return internal::SerializeBoolValue(NativeValue(), value);
}

absl::StatusOr<absl::Cord> BoolValueView::Serialize() const {
  absl::Cord value;
  CEL_RETURN_IF_ERROR(SerializeTo(value));
  return value;
}

absl::StatusOr<std::string> BoolValueView::GetTypeUrl(
    absl::string_view prefix) const {
  return MakeTypeUrlWithPrefix(prefix, "google.protobuf.BoolValue");
}

absl::StatusOr<Any> BoolValueView::ConvertToAny(
    absl::string_view prefix) const {
  CEL_ASSIGN_OR_RETURN(auto value, Serialize());
  CEL_ASSIGN_OR_RETURN(auto type_url, GetTypeUrl(prefix));
  return MakeAny(std::move(type_url), std::move(value));
}

absl::StatusOr<Json> BoolValueView::ConvertToJson() const {
  return NativeValue();
}

}  // namespace cel
