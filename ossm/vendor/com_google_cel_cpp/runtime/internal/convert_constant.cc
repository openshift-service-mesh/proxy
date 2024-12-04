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

#include "runtime/internal/convert_constant.h"

#include <cstdint>
#include <string>

#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "absl/types/variant.h"
#include "base/ast_internal/expr.h"
#include "base/handle.h"
#include "base/value.h"
#include "base/value_factory.h"
#include "eval/internal/errors.h"

namespace cel::runtime_internal {
namespace {
using ::cel::ast_internal::Constant;

struct ConvertVisitor {
  cel::ValueFactory& value_factory;

  absl::StatusOr<cel::Handle<cel::Value>> operator()(
      const cel::ast_internal::NullValue& value) {
    return value_factory.GetNullValue();
  }
  absl::StatusOr<cel::Handle<cel::Value>> operator()(bool value) {
    return value_factory.CreateBoolValue(value);
  }
  absl::StatusOr<cel::Handle<cel::Value>> operator()(int64_t value) {
    return value_factory.CreateIntValue(value);
  }
  absl::StatusOr<cel::Handle<cel::Value>> operator()(uint64_t value) {
    return value_factory.CreateUintValue(value);
  }
  absl::StatusOr<cel::Handle<cel::Value>> operator()(double value) {
    return value_factory.CreateDoubleValue(value);
  }
  absl::StatusOr<cel::Handle<cel::Value>> operator()(const std::string& value) {
    return value_factory.CreateUncheckedStringValue(value);
  }
  absl::StatusOr<cel::Handle<cel::Value>> operator()(
      const cel::ast_internal::Bytes& value) {
    return value_factory.CreateBytesValue(value.bytes);
  }
  absl::StatusOr<cel::Handle<cel::Value>> operator()(
      const absl::Duration duration) {
    if (duration >= kDurationHigh || duration <= kDurationLow) {
      return value_factory.CreateErrorValue(*DurationOverflowError());
    }
    return value_factory.CreateUncheckedDurationValue(duration);
  }
  absl::StatusOr<cel::Handle<cel::Value>> operator()(
      const absl::Time timestamp) {
    return value_factory.CreateUncheckedTimestampValue(timestamp);
  }
};

}  // namespace
// Converts an Ast constant into a runtime value, managed according to the
// given value factory.
//
// A status maybe returned if value creation fails.
absl::StatusOr<Handle<Value>> ConvertConstant(const Constant& constant,
                                              ValueFactory& value_factory) {
  return absl::visit(ConvertVisitor{value_factory}, constant.constant_kind());
}

}  // namespace cel::runtime_internal
