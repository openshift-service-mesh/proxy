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

#include "extensions/math_ext.h"

#include <cstdint>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "eval/public/cel_function_registry.h"
#include "eval/public/cel_number.h"
#include "eval/public/cel_options.h"
#include "eval/public/cel_value.h"
#include "eval/public/portable_cel_function_adapter.h"
#include "internal/status_macros.h"
#include "google/protobuf/arena.h"

namespace cel::extensions {

namespace {

using ::google::api::expr::runtime::CelFunctionRegistry;
using ::google::api::expr::runtime::CelList;
using ::google::api::expr::runtime::CelNumber;
using ::google::api::expr::runtime::CelValue;
using ::google::api::expr::runtime::CreateErrorValue;
using ::google::api::expr::runtime::GetNumberFromCelValue;
using ::google::api::expr::runtime::InterpreterOptions;
using ::google::api::expr::runtime::PortableBinaryFunctionAdapter;
using ::google::api::expr::runtime::PortableUnaryFunctionAdapter;
using ::google::protobuf::Arena;


static constexpr char kMathMin[] = "math.@min";
static constexpr char kMathMax[] = "math.@max";

struct ToValueVisitor {
  CelValue operator()(uint64_t v) const { return CelValue::CreateUint64(v); }
  CelValue operator()(int64_t v) const { return CelValue::CreateInt64(v); }
  CelValue operator()(double v) const { return CelValue::CreateDouble(v); }
};

CelValue NumberToValue(CelNumber number) {
  return number.visit<CelValue>(ToValueVisitor{});
}

absl::StatusOr<CelNumber> ValueToNumber(const CelValue value,
                                        absl::string_view function) {
  absl::optional<CelNumber> current = GetNumberFromCelValue(value);
  if (!current.has_value()) {
    return absl::InvalidArgumentError(
        absl::StrCat(function, " arguments must be numeric"));
  }
  return *current;
}

CelNumber MinNumber(CelNumber v1, CelNumber v2) {
  if (v2 < v1) {
    return v2;
  }
  return v1;
}

CelValue MinValue(CelNumber v1, CelNumber v2) {
  return NumberToValue(MinNumber(v1, v2));
}

template <typename T>
CelValue Identity(Arena *arena, T v1) {
  return NumberToValue(CelNumber(v1));
}

template <typename T, typename U>
CelValue Min(Arena *arena, T v1, U v2) {
  return MinValue(CelNumber(v1), CelNumber(v2));
}

CelValue MinList(Arena *arena, const CelList *values) {
  if (values->empty()) {
    return CreateErrorValue(arena, "math.@min argument must not be empty",
                            absl::StatusCode::kInvalidArgument);
  }
  CelValue value = values->Get(arena, 0);
  absl::StatusOr<CelNumber> current = ValueToNumber(value, kMathMin);
  if (!current.ok()) {
    return CreateErrorValue(arena, current.status());
  }
  if (values->size() == 1) {
    return value;
  }
  CelNumber min = *current;
  for (int i = 1; i < values->size(); ++i) {
    CelValue value = values->Get(arena, i);
    absl::StatusOr<CelNumber> other = ValueToNumber(value, kMathMin);
    if (!other.ok()) {
      return CreateErrorValue(arena, other.status());
    }
    min = MinNumber(min, *other);
  }
  return NumberToValue(min);
}

CelNumber MaxNumber(CelNumber v1, CelNumber v2) {
  if (v2 > v1) {
    return v2;
  }
  return v1;
}

CelValue MaxValue(CelNumber v1, CelNumber v2) {
  return NumberToValue(MaxNumber(v1, v2));
}

template <typename T, typename U>
CelValue Max(Arena *arena, T v1, U v2) {
  return MaxValue(CelNumber(v1), CelNumber(v2));
}

CelValue MaxList(Arena *arena, const CelList *values) {
  if (values->empty()) {
    return CreateErrorValue(arena, "math.@max argument must not be empty",
                            absl::StatusCode::kInvalidArgument);
  }
  CelValue value = values->Get(arena, 0);
  absl::StatusOr<CelNumber> current = ValueToNumber(value, kMathMax);
  if (!current.ok()) {
    return CreateErrorValue(arena, current.status());
  }
  if (values->size() == 1) {
    return value;
  }
  CelNumber max = *current;
  for (int i = 1; i < values->size(); ++i) {
    CelValue value = values->Get(arena, i);
    absl::StatusOr<CelNumber> other = ValueToNumber(value, kMathMax);
    if (!other.ok()) {
      return CreateErrorValue(arena, other.status());
    }
    max = MaxNumber(max, *other);
  }
  return NumberToValue(max);
}

template <typename T, typename U>
absl::Status RegisterCrossNumericMin(CelFunctionRegistry *registry) {
  CEL_RETURN_IF_ERROR(
      registry->Register(PortableBinaryFunctionAdapter<CelValue, T, U>::Create(
          kMathMin, /*receiver_style=*/false, &Min<T, U>)));

  CEL_RETURN_IF_ERROR(
      registry->Register(PortableBinaryFunctionAdapter<CelValue, U, T>::Create(
          kMathMin, /*receiver_style=*/false, &Min<U, T>)));

  return absl::OkStatus();
}

template <typename T, typename U>
absl::Status RegisterCrossNumericMax(CelFunctionRegistry *registry) {
  CEL_RETURN_IF_ERROR(
      registry->Register(PortableBinaryFunctionAdapter<CelValue, T, U>::Create(
          kMathMax, /*receiver_style=*/false, &Max<T, U>)));

  CEL_RETURN_IF_ERROR(
      registry->Register(PortableBinaryFunctionAdapter<CelValue, U, T>::Create(
          kMathMax, /*receiver_style=*/false, &Max<U, T>)));

  return absl::OkStatus();
}

}  // namespace

absl::Status RegisterMathExtensionFunctions(CelFunctionRegistry *registry,
                                            const InterpreterOptions &options) {
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableUnaryFunctionAdapter<CelValue, int64_t>::Create(
          kMathMin, /*receiver_style=*/false, &Identity<int64_t>)));
  CEL_RETURN_IF_ERROR(
      registry->Register(PortableUnaryFunctionAdapter<CelValue, double>::Create(
          kMathMin, /*receiver_style=*/false, &Identity<double>)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableUnaryFunctionAdapter<CelValue, uint64_t>::Create(
          kMathMin, /*receiver_style=*/false, &Identity<uint64_t>)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableBinaryFunctionAdapter<CelValue, int64_t, int64_t>::Create(
          kMathMin, /*receiver_style=*/false, &Min<int64_t, int64_t>)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableBinaryFunctionAdapter<CelValue, double, double>::Create(
          kMathMin, /*receiver_style=*/false, &Min<double, double>)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableBinaryFunctionAdapter<CelValue, uint64_t, uint64_t>::Create(
          kMathMin, /*receiver_style=*/false, &Min<uint64_t, uint64_t>)));
  CEL_RETURN_IF_ERROR((RegisterCrossNumericMin<int64_t, uint64_t>(registry)));
  CEL_RETURN_IF_ERROR((RegisterCrossNumericMin<int64_t, double>(registry)));
  CEL_RETURN_IF_ERROR((RegisterCrossNumericMin<double, uint64_t>(registry)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableUnaryFunctionAdapter<CelValue, const CelList *>::Create(
          kMathMin, false, MinList)));

  CEL_RETURN_IF_ERROR(registry->Register(
      PortableUnaryFunctionAdapter<CelValue, int64_t>::Create(
          kMathMax, /*receiver_style=*/false, &Identity<int64_t>)));
  CEL_RETURN_IF_ERROR(
      registry->Register(PortableUnaryFunctionAdapter<CelValue, double>::Create(
          kMathMax, /*receiver_style=*/false, &Identity<double>)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableUnaryFunctionAdapter<CelValue, uint64_t>::Create(
          kMathMax, /*receiver_style=*/false, &Identity<uint64_t>)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableBinaryFunctionAdapter<CelValue, int64_t, int64_t>::Create(
          kMathMax, /*receiver_style=*/false, &Max<int64_t, int64_t>)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableBinaryFunctionAdapter<CelValue, double, double>::Create(
          kMathMax, /*receiver_style=*/false, &Max<double, double>)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableBinaryFunctionAdapter<CelValue, uint64_t, uint64_t>::Create(
          kMathMax, /*receiver_style=*/false, &Max<uint64_t, uint64_t>)));
  CEL_RETURN_IF_ERROR((RegisterCrossNumericMax<int64_t, uint64_t>(registry)));
  CEL_RETURN_IF_ERROR((RegisterCrossNumericMax<int64_t, double>(registry)));
  CEL_RETURN_IF_ERROR((RegisterCrossNumericMax<double, uint64_t>(registry)));
  CEL_RETURN_IF_ERROR(registry->Register(
      PortableUnaryFunctionAdapter<CelValue, const CelList *>::Create(
          kMathMax, false, MaxList)));

  return absl::OkStatus();
}


}  // namespace cel::extensions
