//
// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "runtime/internal/mutable_list_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "base/types/opaque_type.h"
#include "base/value.h"
#include "base/values/list_value_builder.h"
#include "common/native_type.h"

namespace cel::runtime_internal {
using ::cel::NativeTypeId;

bool MutableListType::Is(const cel::Type& type) {
  return OpaqueType::Is(type) &&
         OpaqueType::TypeId(static_cast<const OpaqueType&>(type)) ==
             cel::NativeTypeId::For<MutableListType>();
}

NativeTypeId MutableListType::GetNativeTypeId() const {
  return cel::NativeTypeId::For<MutableListType>();
}

MutableListValue::MutableListValue(
    cel::Handle<MutableListType> type,
    absl::Nonnull<std::unique_ptr<cel::ListValueBuilderInterface>> list_builder)
    : cel::OpaqueValue(std::move(type)),
      list_builder_(std::move(list_builder)) {}

absl::Status MutableListValue::Append(cel::Handle<cel::Value> element) {
  return list_builder_->Add(std::move(element));
}

absl::StatusOr<cel::Handle<cel::ListValue>> MutableListValue::Build() && {
  return std::move(*list_builder_).Build();
}

std::string MutableListValue::DebugString() const {
  return list_builder_->DebugString();
}

NativeTypeId MutableListValue::GetNativeTypeId() const {
  return cel::NativeTypeId::For<MutableListValue>();
}

bool MutableListValue::Is(const cel::Value& value) {
  return OpaqueValue::Is(value) &&
         OpaqueValue::TypeId(static_cast<const OpaqueValue&>(value)) ==
             cel::NativeTypeId::For<MutableListValue>();
}

}  // namespace cel::runtime_internal
