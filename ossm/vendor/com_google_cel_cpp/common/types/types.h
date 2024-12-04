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

// IWYU pragma: private

#ifndef THIRD_PARTY_CEL_CPP_COMMON_TYPES_TYPES_H_
#define THIRD_PARTY_CEL_CPP_COMMON_TYPES_TYPES_H_

#include <type_traits>

#include "absl/base/attributes.h"
#include "absl/types/variant.h"

namespace cel {

class TypeInterface;
class OpaqueTypeInterface;

class Type;
class AnyType;
class BoolType;
class BoolWrapperType;
class BytesType;
class BytesWrapperType;
class DoubleType;
class DoubleWrapperType;
class DurationType;
class DynType;
class ErrorType;
class IntType;
class IntWrapperType;
class ListType;
class MapType;
class NullType;
class OpaqueType;
class StringType;
class StringWrapperType;
class StructType;
class TimestampType;
class TypeType;
class UintType;
class UintWrapperType;
class UnknownType;

class TypeView;
class AnyTypeView;
class BoolTypeView;
class BoolWrapperTypeView;
class BytesTypeView;
class BytesWrapperTypeView;
class DoubleTypeView;
class DoubleWrapperTypeView;
class DurationTypeView;
class DynTypeView;
class ErrorTypeView;
class IntTypeView;
class IntWrapperTypeView;
class ListTypeView;
class MapTypeView;
class NullTypeView;
class OpaqueTypeView;
class OptionalTypeView;
class StringTypeView;
class StringWrapperTypeView;
class StructTypeView;
class TimestampTypeView;
class TypeTypeView;
class UintTypeView;
class UintWrapperTypeView;
class UnknownTypeView;

namespace common_internal {

template <typename Base, typename Derived>
struct IsDerivedFrom
    : std::bool_constant<
          std::conjunction_v<std::negation<std::is_same<Base, Derived>>,
                             std::is_base_of<Base, Derived>>> {};

template <typename Base, typename Derived>
inline constexpr bool IsDerivedFromV = IsDerivedFrom<Base, Derived>::value;

template <typename T>
struct IsTypeInterface : IsDerivedFrom<TypeInterface, T> {};

template <typename T>
inline constexpr bool IsTypeInterfaceV = IsTypeInterface<T>::value;

template <typename T>
struct IsTypeAlternative
    : std::bool_constant<std::disjunction_v<
          std::is_same<AnyType, T>, std::is_same<BoolType, T>,
          std::is_same<BoolWrapperType, T>, std::is_same<BytesType, T>,
          std::is_same<BytesWrapperType, T>, std::is_same<DoubleType, T>,
          std::is_same<DoubleWrapperType, T>, std::is_same<DurationType, T>,
          std::is_same<DynType, T>, std::is_same<ErrorType, T>,
          std::is_same<IntType, T>, std::is_same<IntWrapperType, T>,
          std::is_same<ListType, T>, std::is_same<MapType, T>,
          std::is_same<NullType, T>, std::is_base_of<OpaqueType, T>,
          std::is_same<StringType, T>, std::is_same<StringWrapperType, T>,
          std::is_base_of<StructType, T>, std::is_same<TimestampType, T>,
          std::is_same<TypeType, T>, std::is_same<UintType, T>,
          std::is_same<UintWrapperType, T>, std::is_same<UnknownType, T>>> {};

template <typename T>
inline constexpr bool IsTypeAlternativeV = IsTypeAlternative<T>::value;

using TypeVariant =
    absl::variant<absl::monostate, AnyType, BoolType, BoolWrapperType,
                  BytesType, BytesWrapperType, DoubleType, DoubleWrapperType,
                  DurationType, DynType, ErrorType, IntType, IntWrapperType,
                  ListType, MapType, NullType, OpaqueType, StringType,
                  StringWrapperType, StructType, TimestampType, TypeType,
                  UintType, UintWrapperType, UnknownType>;

template <typename T>
struct IsTypeViewAlternative
    : std::bool_constant<std::disjunction_v<
          std::is_same<AnyTypeView, T>, std::is_same<BoolTypeView, T>,
          std::is_same<BoolWrapperTypeView, T>, std::is_same<BytesTypeView, T>,
          std::is_same<BytesWrapperTypeView, T>,
          std::is_same<DoubleTypeView, T>,
          std::is_same<DoubleWrapperTypeView, T>,
          std::is_same<DurationTypeView, T>, std::is_same<DynTypeView, T>,
          std::is_same<ErrorTypeView, T>, std::is_same<IntTypeView, T>,
          std::is_same<IntWrapperTypeView, T>, std::is_same<ListTypeView, T>,
          std::is_same<MapTypeView, T>, std::is_same<NullTypeView, T>,
          std::is_base_of<OpaqueTypeView, T>, std::is_same<StringTypeView, T>,
          std::is_same<StringWrapperTypeView, T>,
          std::is_base_of<StructTypeView, T>,
          std::is_same<TimestampTypeView, T>, std::is_same<TypeTypeView, T>,
          std::is_same<UintTypeView, T>, std::is_same<UintWrapperTypeView, T>,
          std::is_same<UnknownTypeView, T>>> {};

template <typename T>
inline constexpr bool IsTypeViewAlternativeV = IsTypeViewAlternative<T>::value;

using TypeViewVariant = absl::variant<
    absl::monostate, AnyTypeView, BoolTypeView, BoolWrapperTypeView,
    BytesTypeView, BytesWrapperTypeView, DoubleTypeView, DoubleWrapperTypeView,
    DurationTypeView, DynTypeView, ErrorTypeView, IntTypeView,
    IntWrapperTypeView, ListTypeView, MapTypeView, NullTypeView, OpaqueTypeView,
    StringTypeView, StringWrapperTypeView, StructTypeView, TimestampTypeView,
    TypeTypeView, UintTypeView, UintWrapperTypeView, UnknownTypeView>;

// Get the base type alternative for the given alternative or interface. The
// base type alternative is the type stored in the `TypeVariant`.
template <typename T, typename = void>
struct BaseTypeAlternativeFor {
  static_assert(IsTypeAlternativeV<T>);
  using type = T;
};

template <typename T>
struct BaseTypeAlternativeFor<T, std::enable_if_t<IsTypeViewAlternativeV<T>>>
    : BaseTypeAlternativeFor<typename T::alternative_type> {};

template <typename T>
struct BaseTypeAlternativeFor<T, std::enable_if_t<IsTypeInterfaceV<T>>>
    : BaseTypeAlternativeFor<typename T::alternative_type> {};

template <typename T>
struct BaseTypeAlternativeFor<
    T, std::enable_if_t<std::is_base_of_v<OpaqueType, T>>> {
  using type = OpaqueType;
};

template <typename T>
struct BaseTypeAlternativeFor<
    T, std::enable_if_t<std::is_base_of_v<StructType, T>>> {
  using type = StructType;
};

template <typename T>
using BaseTypeAlternativeForT = typename BaseTypeAlternativeFor<T>::type;

// Get the base type view alternative for the given alternative or interface.
// The base type view alternative is the type stored in the `TypeViewVariant`.
template <typename T, typename = void>
struct BaseTypeViewAlternativeFor {
  static_assert(IsTypeViewAlternativeV<T>);
  using type = T;
};

template <typename T>
struct BaseTypeViewAlternativeFor<T, std::enable_if_t<IsTypeAlternativeV<T>>>
    : BaseTypeViewAlternativeFor<typename T::view_alternative_type> {};

template <typename T>
struct BaseTypeViewAlternativeFor<T, std::enable_if_t<IsTypeInterfaceV<T>>>
    : BaseTypeViewAlternativeFor<typename T::view_alternative_type> {};

template <typename T>
struct BaseTypeViewAlternativeFor<
    T, std::enable_if_t<std::is_base_of_v<OpaqueTypeView, T>>> {
  using type = OpaqueTypeView;
};

template <typename T>
struct BaseTypeViewAlternativeFor<
    T, std::enable_if_t<std::is_base_of_v<StructTypeView, T>>> {
  using type = StructTypeView;
};

template <typename T>
using BaseTypeViewAlternativeForT =
    typename BaseTypeViewAlternativeFor<T>::type;

ABSL_ATTRIBUTE_PURE_FUNCTION ListTypeView GetDynListType();

ABSL_ATTRIBUTE_PURE_FUNCTION MapTypeView GetDynDynMapType();

ABSL_ATTRIBUTE_PURE_FUNCTION OptionalTypeView GetDynOptionalType();

}  // namespace common_internal

}  // namespace cel

#endif  // THIRD_PARTY_CEL_CPP_COMMON_TYPES_TYPES_H_
