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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "common/any.h"
#include "common/json.h"
#include "common/type.h"
#include "common/value.h"

namespace cel {

absl::StatusOr<size_t> UnknownValue::GetSerializedSize() const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::Status UnknownValue::SerializeTo(absl::Cord&) const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::StatusOr<absl::Cord> UnknownValue::Serialize() const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::StatusOr<std::string> UnknownValue::GetTypeUrl(absl::string_view) const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::StatusOr<Any> UnknownValue::ConvertToAny(absl::string_view) const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::StatusOr<Json> UnknownValue::ConvertToJson() const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is not convertable to JSON"));
}

absl::StatusOr<size_t> UnknownValueView::GetSerializedSize() const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::Status UnknownValueView::SerializeTo(absl::Cord&) const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::StatusOr<absl::Cord> UnknownValueView::Serialize() const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::StatusOr<std::string> UnknownValueView::GetTypeUrl(
    absl::string_view) const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::StatusOr<Any> UnknownValueView::ConvertToAny(absl::string_view) const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is unserializable"));
}

absl::StatusOr<Json> UnknownValueView::ConvertToJson() const {
  return absl::FailedPreconditionError(
      absl::StrCat(type().name(), " is not convertable to JSON"));
}

}  // namespace cel
