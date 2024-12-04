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

// IWYU pragma: private, include "base/value.h"

#ifndef THIRD_PARTY_CEL_CPP_BASE_INTERNAL_VALUE_H_
#define THIRD_PARTY_CEL_CPP_BASE_INTERNAL_VALUE_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <type_traits>

#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/variant.h"
#include "base/handle.h"
#include "base/internal/data.h"
#include "base/internal/type.h"
#include "common/native_type.h"

namespace cel {

class Type;
class BytesValue;
class StringValue;
class StructValue;
class ListValue;
class MapValue;
class UnknownValue;

namespace base_internal {

template <typename T, typename U>
class SimpleValue;

class ValueHandle;

NativeTypeId GetStructValueTypeId(const StructValue& struct_value);

NativeTypeId GetListValueTypeId(const ListValue& list_value);

NativeTypeId GetMapValueTypeId(const MapValue& map_value);

static_assert(std::is_trivially_copyable_v<absl::Duration>,
              "absl::Duration must be trivially copyable.");
static_assert(std::is_trivially_destructible_v<absl::Duration>,
              "absl::Duration must be trivially destructible.");

static_assert(std::is_trivially_copyable_v<absl::Time>,
              "absl::Time must be trivially copyable.");
static_assert(std::is_trivially_destructible_v<absl::Time>,
              "absl::Time must be trivially destructible.");

static_assert(std::is_trivially_copyable_v<absl::string_view>,
              "absl::string_view must be trivially copyable.");
static_assert(std::is_trivially_destructible_v<absl::string_view>,
              "absl::string_view must be trivially destructible.");

struct InlineValue final {
  uintptr_t vptr;
  union {
    bool bool_value;
    int64_t int64_value;
    uint64_t uint64_value;
    double double_value;
    uintptr_t pointer_value;
    absl::Duration duration_value;
    absl::Time time_value;
    absl::Status status_value;
    absl::Cord cord_value;
    struct {
      absl::string_view string_value;
      uintptr_t owner;
    } string_value;
    AnyType type_value;
    struct {
      AnyType type;
      int64_t number;
    } enum_value;
  };
};

inline constexpr size_t kValueInlineSize = sizeof(InlineValue);
inline constexpr size_t kValueInlineAlign = alignof(InlineValue);

static_assert(kValueInlineSize <= 32,
              "Size of an inline value should be less than 32 bytes.");
static_assert(kValueInlineAlign <= alignof(std::max_align_t),
              "Alignment of an inline value should not be overaligned.");

using AnyValue = AnyData<kValueInlineSize, kValueInlineAlign>;

// Metaprogramming utility for interacting with Value.
//
// ValueTraits<T>::type is an alias for T.
// ValueTraits<T>::type_type is the corresponding Type for T.
// ValueTraits<T>::underlying_type is the underlying C++ primitive for T if it
// exists, otherwise void. ValueTraits<T>::DebugString accepts type or
// underlying_type and returns the debug string.
template <typename T>
struct ValueTraits;

class InlinedCordBytesValue;
class InlinedStringViewBytesValue;
class StringBytesValue;
class InlinedCordStringValue;
class InlinedStringViewStringValue;
class StringStringValue;
class LegacyStructValue;
class AbstractStructValue;
class LegacyListValue;
class AbstractListValue;
class LegacyMapValue;
class AbstractMapValue;
class LegacyTypeValue;
class ModernTypeValue;

using StringValueRep =
    absl::variant<absl::string_view, std::reference_wrapper<const absl::Cord>>;
using BytesValueRep =
    absl::variant<absl::string_view, std::reference_wrapper<const absl::Cord>>;
struct UnknownSetImpl;

// Enumeration used to differentiate between BytesValue's multiple inline
// non-trivial implementations.
enum class InlinedBytesValueVariant {
  kCord = 0,
  kStringView,
};

// Enumeration used to differentiate between StringValue's multiple inline
// non-trivial implementations.
enum class InlinedStringValueVariant {
  kCord = 0,
  kStringView,
};

// Enumeration used to differentiate between TypeValue's multiple inline
// non-trivial implementations.
enum class InlinedTypeValueVariant {
  kLegacy = 0,
  kModern,
};

}  // namespace base_internal

namespace interop_internal {

base_internal::StringValueRep GetStringValueRep(
    const Handle<StringValue>& value);
base_internal::BytesValueRep GetBytesValueRep(const Handle<BytesValue>& value);
std::shared_ptr<base_internal::UnknownSetImpl> GetUnknownValueImpl(
    const Handle<UnknownValue>& value);
void SetUnknownValueImpl(Handle<UnknownValue>& value,
                         std::shared_ptr<base_internal::UnknownSetImpl> impl);

struct ErrorValueAccess;
struct UnknownValueAccess;

}  // namespace interop_internal

}  // namespace cel

#define CEL_INTERNAL_VALUE_DECL(name) extern template class Handle<name>

#define CEL_INTERNAL_VALUE_IMPL(name) template class Handle<name>

#define CEL_INTERNAL_DECLARE_VALUE(base, derived)       \
 public:                                                \
  static bool Is(const ::cel::Value& value);            \
                                                        \
  using ::cel::base##Value::Is;                         \
                                                        \
  static const derived& Cast(const cel::Value& value) { \
    ABSL_ASSERT(Is(value));                             \
    return static_cast<const derived&>(value);          \
  }                                                     \
                                                        \
 private:                                               \
  friend class ::cel::base_internal::ValueHandle;       \
                                                        \
  ::cel::NativeTypeId GetNativeTypeId() const override;

#define CEL_INTERNAL_IMPLEMENT_VALUE(base, derived)                           \
  static_assert(::std::is_base_of_v<::cel::base##Value, derived>,             \
                #derived " must inherit from cel::" #base "Value");           \
  static_assert(!::std::is_abstract_v<derived>, "this must not be abstract"); \
                                                                              \
  bool derived::Is(const ::cel::Value& value) {                               \
    return value.kind() == ::cel::Kind::k##base &&                            \
           ::cel::base_internal::Get##base##ValueTypeId(                      \
               static_cast<const ::cel::base##Value&>(value)) ==              \
               ::cel::NativeTypeId::For<derived>();                           \
  }                                                                           \
                                                                              \
  ::cel::NativeTypeId derived::GetNativeTypeId() const {                      \
    return ::cel::NativeTypeId::For<derived>();                               \
  }

#endif  // THIRD_PARTY_CEL_CPP_BASE_INTERNAL_VALUE_H_
