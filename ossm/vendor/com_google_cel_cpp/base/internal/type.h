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

// IWYU pragma: private, include "base/type.h"

#ifndef THIRD_PARTY_CEL_CPP_BASE_INTERNAL_TYPE_H_
#define THIRD_PARTY_CEL_CPP_BASE_INTERNAL_TYPE_H_

#include <cstdint>

#include "base/internal/data.h"
#include "base/kind.h"
#include "common/native_type.h"

namespace cel {

class Value;
class EnumType;
class StructType;

namespace base_internal {

class TypeHandle;

class ListTypeImpl;
class MapTypeImpl;
class LegacyStructType;
class AbstractStructType;
class LegacyStructValue;
class AbstractStructValue;
class LegacyListType;
class ModernListType;
class LegacyMapType;
class ModernMapType;
struct FieldIdFactory;

template <TypeKind K>
class SimpleType;
template <typename T, typename U>
class SimpleValue;

NativeTypeId GetEnumTypeTypeId(const EnumType& enum_type);

NativeTypeId GetStructTypeTypeId(const StructType& struct_type);

struct InlineType final {
  uintptr_t vptr;
  union {
    uintptr_t legacy;
  };
};

inline constexpr size_t kTypeInlineSize = sizeof(InlineType);
inline constexpr size_t kTypeInlineAlign = alignof(InlineType);

static_assert(kTypeInlineSize <= 16,
              "Size of an inline type should be less than 16 bytes.");
static_assert(kTypeInlineAlign <= alignof(std::max_align_t),
              "Alignment of an inline type should not be overaligned.");

using AnyType = AnyData<kTypeInlineSize, kTypeInlineAlign>;

// Metaprogramming utility for interacting with Type.
//
// TypeTraits<T>::type is an alias for T.
// TypeTraits<T>::value_type is the corresponding Value for T.
template <typename T>
struct TypeTraits;

}  // namespace base_internal

}  // namespace cel

#define CEL_INTERNAL_TYPE_DECL(name) extern template class Handle<name>

#define CEL_INTERNAL_TYPE_IMPL(name) template class Handle<name>

#define CEL_INTERNAL_DECLARE_TYPE(base, derived)      \
 public:                                              \
  static bool Is(const ::cel::Type& type);            \
                                                      \
  using ::cel::base##Type::Is;                        \
                                                      \
  static const derived& Cast(const cel::Type& type) { \
    ABSL_ASSERT(Is(type));                            \
    return static_cast<const derived&>(type);         \
  }                                                   \
                                                      \
 private:                                             \
  friend class ::cel::base_internal::TypeHandle;      \
                                                      \
  ::cel::NativeTypeId GetNativeTypeId() const override;

#define CEL_INTERNAL_IMPLEMENT_TYPE(base, derived)                            \
  static_assert(::std::is_base_of_v<::cel::base##Type, derived>,              \
                #derived " must inherit from cel::" #base "Type");            \
  static_assert(!::std::is_abstract_v<derived>, "this must not be abstract"); \
                                                                              \
  bool derived::Is(const ::cel::Type& type) {                                 \
    return type.kind() == ::cel::TypeKind::k##base &&                         \
           ::cel::base_internal::Get##base##TypeTypeId(                       \
               static_cast<const ::cel::base##Type&>(type)) ==                \
               ::cel::NativeTypeId::For<derived>();                           \
  }                                                                           \
                                                                              \
  ::cel::NativeTypeId derived::GetNativeTypeId() const {                      \
    return ::cel::NativeTypeId::For<derived>();                               \
  }

#endif  // THIRD_PARTY_CEL_CPP_BASE_INTERNAL_TYPE_H_
