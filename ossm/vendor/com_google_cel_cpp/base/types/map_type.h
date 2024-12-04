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

#ifndef THIRD_PARTY_CEL_CPP_BASE_TYPES_MAP_TYPE_H_
#define THIRD_PARTY_CEL_CPP_BASE_TYPES_MAP_TYPE_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/base/attributes.h"
#include "absl/base/nullability.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "base/handle.h"
#include "base/internal/data.h"
#include "base/kind.h"
#include "base/memory.h"
#include "base/type.h"

namespace cel {

class MemoryManager;
class TypeFactory;
class MapValue;
class ValueFactory;
class MapValueBuilderInterface;

// MapType represents a map type. A map is container of key and value pairs
// where each key appears at most once.
class MapType : public Type,
                public base_internal::EnableHandleFromThis<MapType, MapType> {
 public:
  /** Checks whether `type` is valid for use as a map key. Returns
   * `INVALID_ARGUMENT` is it is not, otherwise `OK`. */
  static absl::Status CheckKey(const Type& type);

  static constexpr TypeKind kKind = TypeKind::kMap;

  static bool Is(const Type& type) { return type.kind() == kKind; }

  using Type::Is;

  static const MapType& Cast(const Type& type) {
    ABSL_DCHECK(Is(type)) << "cannot cast " << type.name() << " to map";
    return static_cast<const MapType&>(type);
  }

  TypeKind kind() const { return kKind; }

  absl::string_view name() const { return TypeKindToString(kind()); }

  std::string DebugString() const;

  absl::StatusOr<Handle<MapValue>> NewValueFromAny(
      ValueFactory& value_factory, const absl::Cord& value) const;

  // Returns the type of the keys in the map.
  const Handle<Type>& key() const;

  // Returns the type of the values in the map.
  const Handle<Type>& value() const;

  absl::StatusOr<absl::Nonnull<std::unique_ptr<MapValueBuilderInterface>>>
  NewValueBuilder(ValueFactory& value_factory ABSL_ATTRIBUTE_LIFETIME_BOUND)
      const ABSL_ATTRIBUTE_LIFETIME_BOUND;

 private:
  friend class Type;
  friend class MemoryManager;
  friend class TypeFactory;
  friend class base_internal::TypeHandle;
  friend class base_internal::LegacyMapType;
  friend class base_internal::ModernMapType;

  // See Type::aliases().
  absl::Span<const absl::string_view> aliases() const;

  MapType() = default;
};

CEL_INTERNAL_TYPE_DECL(MapType);

namespace base_internal {

// LegacyMapType is used by LegacymapValue for compatibility with the legacy
// API. It's key and value are always the dynamic type regardless of whether the
// the expression is checked or not.
class LegacyMapType final : public MapType, public InlineData {
 public:
  const Handle<Type>& key() const;

  const Handle<Type>& value() const;

 private:
  friend class MemoryManager;
  friend class TypeFactory;
  friend class cel::MapType;
  friend class base_internal::TypeHandle;
  template <size_t Size, size_t Align>
  friend struct AnyData;

  static constexpr uintptr_t kMetadata =
      base_internal::kStoredInline | base_internal::kTrivial |
      (static_cast<uintptr_t>(kKind) << base_internal::kKindShift);

  LegacyMapType() : MapType(), InlineData(kMetadata) {}
};

class ModernMapType final : public MapType, public HeapData {
 public:
  const Handle<Type>& key() const { return key_; }

  const Handle<Type>& value() const { return value_; }

 private:
  friend class cel::MemoryManager;
  friend class TypeFactory;
  friend class cel::MapType;
  friend class base_internal::TypeHandle;

  // Called by Arena-based memory managers to determine whether we actually need
  // our destructor called.
  CEL_INTERNAL_IS_DESTRUCTOR_SKIPPABLE() {
    return Metadata::IsDestructorSkippable(*key()) &&
           Metadata::IsDestructorSkippable(*value());
  }

  explicit ModernMapType(Handle<Type> key, Handle<Type> value);

  const Handle<Type> key_;
  const Handle<Type> value_;
};

}  // namespace base_internal

namespace base_internal {

template <>
struct TypeTraits<MapType> {
  using value_type = MapValue;
};

}  // namespace base_internal

}  // namespace cel

#endif  // THIRD_PARTY_CEL_CPP_BASE_TYPES_MAP_TYPE_H_
