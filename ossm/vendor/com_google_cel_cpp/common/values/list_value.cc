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
#include <memory>
#include <string>

#include "absl/base/nullability.h"
#include "absl/base/optimization.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "common/any.h"
#include "common/value.h"
#include "internal/serialize.h"
#include "internal/status_macros.h"

namespace cel {

class ListValueInterfaceIterator final : public ValueIterator {
 public:
  explicit ListValueInterfaceIterator(const ListValueInterface& interface,
                                      ValueFactory& value_factory)
      : interface_(interface),
        value_factory_(value_factory),
        size_(interface_.Size()) {}

  bool HasNext() override { return index_ < size_; }

  absl::StatusOr<ValueView> Next(Value& scratch) override {
    if (ABSL_PREDICT_FALSE(index_ >= size_)) {
      return absl::FailedPreconditionError(
          "ValueIterator::Next() called when "
          "ValueIterator::HasNext() returns false");
    }
    return interface_.GetImpl(value_factory_, index_++, scratch);
  }

 private:
  const ListValueInterface& interface_;
  ValueFactory& value_factory_;
  const size_t size_;
  size_t index_ = 0;
};

absl::StatusOr<size_t> ListValueInterface::GetSerializedSize() const {
  return absl::UnimplementedError(
      "preflighting serialization size is not implemented by this list");
}

absl::Status ListValueInterface::SerializeTo(absl::Cord& value) const {
  CEL_ASSIGN_OR_RETURN(auto json, ConvertToJsonArray());
  return internal::SerializeListValue(json, value);
}

absl::StatusOr<std::string> ListValueInterface::GetTypeUrl(
    absl::string_view prefix) const {
  return MakeTypeUrlWithPrefix(prefix, "google.protobuf.ListValue");
}

absl::StatusOr<ValueView> ListValueInterface::Get(ValueFactory& value_factory,
                                                  size_t index,
                                                  Value& scratch) const {
  if (ABSL_PREDICT_FALSE(index >= Size())) {
    return absl::InvalidArgumentError("index out of bounds");
  }
  return GetImpl(value_factory, index, scratch);
}

absl::Status ListValueInterface::ForEach(ValueFactory& value_factory,
                                         ForEachCallback callback) const {
  const size_t size = Size();
  for (size_t index = 0; index < size; ++index) {
    Value scratch;
    CEL_ASSIGN_OR_RETURN(auto element, GetImpl(value_factory, index, scratch));
    CEL_ASSIGN_OR_RETURN(auto ok, callback(element));
    if (!ok) {
      break;
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<absl::Nonnull<ValueIteratorPtr>> ListValueInterface::NewIterator(
    ValueFactory& value_factory) const {
  return std::make_unique<ListValueInterfaceIterator>(*this, value_factory);
}

}  // namespace cel
