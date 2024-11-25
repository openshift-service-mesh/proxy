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

absl::StatusOr<size_t> NullValue::GetSerializedSize() const {
  return internal::SerializedValueSize(kJsonNull);
}

absl::Status NullValue::SerializeTo(absl::Cord& value) const {
  return internal::SerializeValue(kJsonNull, value);
}

absl::StatusOr<absl::Cord> NullValue::Serialize() const {
  absl::Cord value;
  CEL_RETURN_IF_ERROR(SerializeTo(value));
  return value;
}

absl::StatusOr<std::string> NullValue::GetTypeUrl(
    absl::string_view prefix) const {
  return MakeTypeUrlWithPrefix(prefix, "google.protobuf.Value");
}

absl::StatusOr<Any> NullValue::ConvertToAny(absl::string_view prefix) const {
  CEL_ASSIGN_OR_RETURN(auto value, Serialize());
  CEL_ASSIGN_OR_RETURN(auto type_url, GetTypeUrl(prefix));
  return MakeAny(std::move(type_url), std::move(value));
}

absl::StatusOr<size_t> NullValueView::GetSerializedSize() const {
  return internal::SerializedValueSize(kJsonNull);
}

absl::Status NullValueView::SerializeTo(absl::Cord& value) const {
  return internal::SerializeValue(kJsonNull, value);
}

absl::StatusOr<absl::Cord> NullValueView::Serialize() const {
  absl::Cord value;
  CEL_RETURN_IF_ERROR(SerializeTo(value));
  return value;
}

absl::StatusOr<std::string> NullValueView::GetTypeUrl(
    absl::string_view prefix) const {
  return MakeTypeUrlWithPrefix(prefix, "google.protobuf.Value");
}

absl::StatusOr<Any> NullValueView::ConvertToAny(
    absl::string_view prefix) const {
  CEL_ASSIGN_OR_RETURN(auto value, Serialize());
  CEL_ASSIGN_OR_RETURN(auto type_url, GetTypeUrl(prefix));
  return MakeAny(std::move(type_url), std::move(value));
}

}  // namespace cel
