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

// IWYU pragma: private, include "common/value.h"
// IWYU pragma: friend "common/value.h"

#ifndef THIRD_PARTY_CEL_CPP_COMMON_VALUES_BYTES_VALUE_H_
#define THIRD_PARTY_CEL_CPP_COMMON_VALUES_BYTES_VALUE_H_

#include <cstddef>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/meta/type_traits.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "common/any.h"
#include "common/internal/shared_byte_string.h"
#include "common/json.h"
#include "common/type.h"
#include "common/value_kind.h"

namespace cel {

class BytesValue;
class BytesValueView;

// `BytesValue` represents values of the primitive `bytes` type.
class BytesValue final {
 public:
  using view_alternative_type = BytesValueView;

  static constexpr ValueKind kKind = ValueKind::kBytes;

  explicit BytesValue(absl::Cord value) noexcept : value_(std::move(value)) {}

  explicit BytesValue(absl::string_view value) noexcept
      : value_(absl::Cord(value)) {}

  template <typename T, typename = std::enable_if_t<std::is_same_v<
                            absl::remove_cvref_t<T>, std::string>>>
  explicit BytesValue(T&& data) : value_(absl::Cord(std::forward<T>(data))) {}

  // Clang exposes `__attribute__((enable_if))` which can be used to detect
  // compile time string constants. When available, we use this to avoid
  // unnecessary copying as `BytesValue(absl::string_view)` makes a copy.
#if ABSL_HAVE_ATTRIBUTE(enable_if)
  template <size_t N>
  explicit BytesValue(const char (&data)[N])
      __attribute__((enable_if(::cel::common_internal::IsStringLiteral(data),
                               "chosen when 'data' is a string literal")))
      : value_(absl::string_view(data)) {}
#endif

  explicit BytesValue(BytesValueView value) noexcept;

  BytesValue() = default;
  BytesValue(const BytesValue&) = default;
  BytesValue(BytesValue&&) = default;
  BytesValue& operator=(const BytesValue&) = default;
  BytesValue& operator=(BytesValue&&) = default;

  constexpr ValueKind kind() const { return kKind; }

  BytesTypeView type() const { return BytesTypeView(); }

  std::string DebugString() const;

  absl::StatusOr<size_t> GetSerializedSize() const;

  absl::Status SerializeTo(absl::Cord& value) const;

  absl::StatusOr<absl::Cord> Serialize() const;

  absl::StatusOr<std::string> GetTypeUrl(
      absl::string_view prefix = kTypeGoogleApisComPrefix) const;

  absl::StatusOr<Any> ConvertToAny(
      absl::string_view prefix = kTypeGoogleApisComPrefix) const;

  absl::StatusOr<Json> ConvertToJson() const;

  std::string NativeString() const { return value_.ToString(); }

  absl::string_view NativeString(
      std::string& scratch
          ABSL_ATTRIBUTE_LIFETIME_BOUND) const ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return value_.ToString(scratch);
  }

  absl::Cord NativeCord() const { return value_.ToCord(); }

  template <typename Visitor>
  std::common_type_t<std::invoke_result_t<Visitor, absl::string_view>,
                     std::invoke_result_t<Visitor, const absl::Cord&>>
  NativeValue(Visitor&& visitor) const {
    return value_.Visit(std::forward<Visitor>(visitor));
  }

  void swap(BytesValue& other) noexcept {
    using std::swap;
    swap(value_, other.value_);
  }

 private:
  friend class BytesValueView;

  common_internal::SharedByteString value_;
};

inline void swap(BytesValue& lhs, BytesValue& rhs) noexcept { lhs.swap(rhs); }

inline std::ostream& operator<<(std::ostream& out, const BytesValue& value) {
  return out << value.DebugString();
}

class BytesValueView final {
 public:
  using alternative_type = BytesValue;

  static constexpr ValueKind kKind = BytesValue::kKind;

  explicit BytesValueView(
      const absl::Cord& value ABSL_ATTRIBUTE_LIFETIME_BOUND) noexcept
      : value_(value) {}

  explicit BytesValueView(absl::string_view value) noexcept : value_(value) {}

  // NOLINTNEXTLINE(google-explicit-constructor)
  BytesValueView(const BytesValue& value ABSL_ATTRIBUTE_LIFETIME_BOUND) noexcept
      : value_(value.value_) {}

  // NOLINTNEXTLINE(google-explicit-constructor)
  BytesValueView& operator=(
      const BytesValue& value ABSL_ATTRIBUTE_LIFETIME_BOUND) {
    value_ = value.value_;
    return *this;
  }

  BytesValueView& operator=(BytesValue&&) = delete;

  BytesValueView() = default;
  BytesValueView(const BytesValueView&) = default;
  BytesValueView(BytesValueView&&) = default;
  BytesValueView& operator=(const BytesValueView&) = default;
  BytesValueView& operator=(BytesValueView&&) = default;

  constexpr ValueKind kind() const { return kKind; }

  BytesTypeView type() const { return BytesTypeView(); }

  std::string DebugString() const;

  absl::StatusOr<size_t> GetSerializedSize() const;

  absl::Status SerializeTo(absl::Cord& value) const;

  absl::StatusOr<absl::Cord> Serialize() const;

  absl::StatusOr<std::string> GetTypeUrl(
      absl::string_view prefix = kTypeGoogleApisComPrefix) const;

  absl::StatusOr<Any> ConvertToAny(
      absl::string_view prefix = kTypeGoogleApisComPrefix) const;

  absl::StatusOr<Json> ConvertToJson() const;

  std::string NativeString() const { return value_.ToString(); }

  absl::string_view NativeString(
      std::string& scratch
          ABSL_ATTRIBUTE_LIFETIME_BOUND) const ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return value_.ToString(scratch);
  }

  absl::Cord NativeCord() const { return value_.ToCord(); }

  template <typename Visitor>
  std::common_type_t<std::invoke_result_t<Visitor, absl::string_view>,
                     std::invoke_result_t<Visitor, const absl::Cord&>>
  NativeValue(Visitor&& visitor) const {
    return value_.Visit(std::forward<Visitor>(visitor));
  }

  void swap(BytesValueView& other) noexcept {
    using std::swap;
    swap(value_, other.value_);
  }

 private:
  friend class BytesValue;

  common_internal::SharedByteStringView value_;
};

inline void swap(BytesValueView& lhs, BytesValueView& rhs) noexcept {
  lhs.swap(rhs);
}

inline std::ostream& operator<<(std::ostream& out, BytesValueView value) {
  return out << value.DebugString();
}

inline BytesValue::BytesValue(BytesValueView value) noexcept
    : value_(value.value_) {}

}  // namespace cel

#endif  // THIRD_PARTY_CEL_CPP_COMMON_VALUES_BYTES_VALUE_H_
