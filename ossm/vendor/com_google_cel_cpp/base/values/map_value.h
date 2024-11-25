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

#ifndef THIRD_PARTY_CEL_CPP_BASE_VALUES_MAP_VALUE_H_
#define THIRD_PARTY_CEL_CPP_BASE_VALUES_MAP_VALUE_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/base/macros.h"
#include "absl/base/nullability.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "base/handle.h"
#include "base/internal/data.h"
#include "base/kind.h"
#include "base/memory.h"
#include "base/owner.h"
#include "base/type.h"
#include "base/types/map_type.h"
#include "base/value.h"
#include "base/values/list_value.h"
#include "common/any.h"
#include "common/json.h"
#include "common/native_type.h"

namespace cel {

class ListValue;
class ValueFactory;
class MemoryManager;
class MapValueBuilderInterface;
template <typename K, typename V>
class MapValueBuilder;

// MapValue represents an instance of cel::MapType.
class MapValue : public Value,
                 public base_internal::EnableHandleFromThis<MapValue> {
 public:
  using BuilderInterface = MapValueBuilderInterface;
  template <typename K, typename V>
  using Builder = MapValueBuilder<K, V>;

  /** Checks whether `value` is valid for use as a map key. Returns
   * `INVALID_ARGUMENT` is it is not, otherwise `OK`. */
  static absl::Status CheckKey(const Value& value);

  static constexpr ValueKind kKind = ValueKind::kMap;

  static bool Is(const Value& value) { return value.kind() == kKind; }

  using Value::Is;

  static const MapValue& Cast(const Value& value) {
    ABSL_DCHECK(Is(value)) << "cannot cast " << value.type()->name()
                           << " to map";
    return static_cast<const MapValue&>(value);
  }

  constexpr ValueKind kind() const { return kKind; }

  Handle<MapType> type() const;

  std::string DebugString() const;

  absl::StatusOr<Any> ConvertToAny(ValueFactory& value_factory) const;

  absl::StatusOr<Json> ConvertToJson(ValueFactory& value_factory) const;

  absl::StatusOr<JsonObject> ConvertToJsonObject(
      ValueFactory& value_factory) const;

  absl::StatusOr<Handle<Value>> ConvertToType(ValueFactory& value_factory,
                                              const Handle<Type>& type) const;

  absl::StatusOr<Handle<Value>> Equals(ValueFactory& value_factory,
                                       const Value& other) const;

  size_t Size() const;

  bool IsEmpty() const;

  // Retrieves the value corresponding to the given key. If the key does not
  // exist, an error value is returned. If the given key type is not
  // compatible with the expected key type, an error value is returned.
  absl::StatusOr<Handle<Value>> Get(ValueFactory& value_factory,
                                    const Handle<Value>& key) const;

  // Retrieves the value corresponding to the given key. If the key does not
  // exist but the key is otherwise valid, an empty handle and false are
  // returned. If the key is an error or unknown, the key is returned along with
  // false. Otherwise the corresponding value and true are returned.
  absl::StatusOr<std::pair<Handle<Value>, bool>> Find(
      ValueFactory& value_factory, const Handle<Value>& key) const;

  absl::StatusOr<Handle<Value>> Has(ValueFactory& value_factory,
                                    const Handle<Value>& key) const;

  absl::StatusOr<Handle<ListValue>> ListKeys(ValueFactory& value_factory) const;

  class Iterator;

  absl::StatusOr<absl::Nonnull<std::unique_ptr<Iterator>>> NewIterator(
      ValueFactory& value_factory
          ABSL_ATTRIBUTE_LIFETIME_BOUND) const ABSL_ATTRIBUTE_LIFETIME_BOUND;

 private:
  friend NativeTypeId base_internal::GetMapValueTypeId(
      const MapValue& map_value);
  friend class base_internal::ValueHandle;
  friend class base_internal::LegacyMapValue;
  friend class base_internal::AbstractMapValue;

  MapValue() = default;

  // Called by CEL_IMPLEMENT_MAP_VALUE() and Is() to perform type checking.
  NativeTypeId GetNativeTypeId() const;
};

// Abstract class describes an iterator which can iterate over the entries in a
// map. A default implementation is provided by `MapValue::NewIterator`, however
// it is likely not as efficient as providing your own implementation.
class MapValue::Iterator {
 public:
  virtual ~Iterator() = default;

  ABSL_MUST_USE_RESULT virtual bool HasNext() = 0;

  virtual absl::StatusOr<Handle<Value>> Next() = 0;
};

CEL_INTERNAL_VALUE_DECL(MapValue);

namespace base_internal {

ABSL_ATTRIBUTE_WEAK size_t LegacyMapValueSize(uintptr_t impl);
ABSL_ATTRIBUTE_WEAK bool LegacyMapValueEmpty(uintptr_t impl);
ABSL_ATTRIBUTE_WEAK absl::StatusOr<absl::optional<Handle<Value>>>
LegacyMapValueGet(uintptr_t impl, ValueFactory& value_factory,
                  const Handle<Value>& key);
ABSL_ATTRIBUTE_WEAK absl::StatusOr<bool> LegacyMapValueHas(
    uintptr_t impl, const Handle<Value>& key);
ABSL_ATTRIBUTE_WEAK absl::StatusOr<Handle<ListValue>> LegacyMapValueListKeys(
    uintptr_t impl, ValueFactory& value_factory);

constexpr absl::string_view kErrNoSuchKey = "Key not found in map";

absl::Status CreateNoSuchKeyError(absl::string_view key);
absl::Status CreateNoSuchKeyError(const Value& value);

class LegacyMapValue final : public MapValue, public InlineData {
 public:
  static bool Is(const Value& value) {
    return value.kind() == kKind &&
           static_cast<const MapValue&>(value).GetNativeTypeId() ==
               NativeTypeId::For<LegacyMapValue>();
  }

  using MapValue::Is;

  static const LegacyMapValue& Cast(const Value& value) {
    ABSL_ASSERT(Is(value));
    return static_cast<const LegacyMapValue&>(value);
  }

  Handle<MapType> type() const;

  std::string DebugString() const;

  absl::StatusOr<Any> ConvertToAny(ValueFactory& value_factory) const;

  absl::StatusOr<JsonObject> ConvertToJsonObject(
      ValueFactory& value_factory) const;

  size_t Size() const;

  bool IsEmpty() const;

  absl::StatusOr<Handle<ListValue>> ListKeys(ValueFactory& value_factory) const;

  absl::StatusOr<absl::Nonnull<std::unique_ptr<Iterator>>> NewIterator(
      ValueFactory& value_factory
          ABSL_ATTRIBUTE_LIFETIME_BOUND) const ABSL_ATTRIBUTE_LIFETIME_BOUND;

  absl::StatusOr<Handle<Value>> Equals(ValueFactory& value_factory,
                                       const Value& other) const;

  constexpr uintptr_t value() const { return impl_; }

 private:
  friend class base_internal::ValueHandle;
  friend class cel::MapValue;
  template <size_t Size, size_t Align>
  friend struct AnyData;

  static constexpr uintptr_t kMetadata =
      kStoredInline | kTrivial | (static_cast<uintptr_t>(kKind) << kKindShift);

  explicit LegacyMapValue(uintptr_t impl)
      : MapValue(), InlineData(kMetadata), impl_(impl) {}

  NativeTypeId GetNativeTypeId() const {
    return NativeTypeId::For<LegacyMapValue>();
  }

  absl::StatusOr<std::pair<Handle<Value>, bool>> FindImpl(
      ValueFactory& value_factory, const Handle<Value>& key) const;

  absl::StatusOr<Handle<Value>> HasImpl(ValueFactory& value_factory,
                                        const Handle<Value>& key) const;

  uintptr_t impl_;
};

class AbstractMapValue : public MapValue,
                         public HeapData,
                         public EnableOwnerFromThis<AbstractMapValue> {
 public:
  static bool Is(const Value& value) {
    return value.kind() == kKind &&
           static_cast<const MapValue&>(value).GetNativeTypeId() !=
               NativeTypeId::For<LegacyMapValue>();
  }

  using MapValue::Is;

  static const AbstractMapValue& Cast(const Value& value) {
    ABSL_ASSERT(Is(value));
    return static_cast<const AbstractMapValue&>(value);
  }

  const Handle<MapType>& type() const { return type_; }

  virtual std::string DebugString() const = 0;

  virtual absl::StatusOr<Any> ConvertToAny(ValueFactory& value_factory) const;

  virtual absl::StatusOr<JsonObject> ConvertToJsonObject(
      ValueFactory& value_factory) const;

  virtual size_t Size() const = 0;

  virtual bool IsEmpty() const { return Size() == 0; }

  virtual absl::StatusOr<Handle<ListValue>> ListKeys(
      ValueFactory& value_factory) const = 0;

  virtual absl::StatusOr<absl::Nonnull<std::unique_ptr<Iterator>>> NewIterator(
      ValueFactory& value_factory
          ABSL_ATTRIBUTE_LIFETIME_BOUND) const ABSL_ATTRIBUTE_LIFETIME_BOUND;

  virtual absl::StatusOr<Handle<Value>> Equals(ValueFactory& value_factory,
                                               const Value& other) const;

 protected:
  explicit AbstractMapValue(Handle<MapType> type);

 private:
  friend class cel::MapValue;
  friend class base_internal::ValueHandle;

  virtual absl::StatusOr<std::pair<Handle<Value>, bool>> FindImpl(
      ValueFactory& value_factory, const Handle<Value>& key) const = 0;

  virtual absl::StatusOr<Handle<Value>> HasImpl(
      ValueFactory& value_factory, const Handle<Value>& key) const = 0;

  // Called by CEL_IMPLEMENT_MAP_VALUE() and Is() to perform type checking.
  virtual NativeTypeId GetNativeTypeId() const = 0;

  const Handle<MapType> type_;
};

inline NativeTypeId GetMapValueTypeId(const MapValue& map_value) {
  return map_value.GetNativeTypeId();
}

}  // namespace base_internal

#define CEL_MAP_VALUE_CLASS ::cel::base_internal::AbstractMapValue

// CEL_DECLARE_MAP_VALUE declares `map_value` as an map value. It must
// be part of the class definition of `map_value`.
//
// class MyMapValue : public CEL_MAP_VALUE_CLASS {
//  ...
// private:
//   CEL_DECLARE_MAP_VALUE(MyMapValue);
// };
#define CEL_DECLARE_MAP_VALUE(map_value) \
  CEL_INTERNAL_DECLARE_VALUE(Map, map_value)

// CEL_IMPLEMENT_MAP_VALUE implements `map_value` as an map
// value. It must be called after the class definition of `map_value`.
//
// class MyMapValue : public CEL_MAP_VALUE_CLASS {
//  ...
// private:
//   CEL_DECLARE_MAP_VALUE(MyMapValue);
// };
//
// CEL_IMPLEMENT_MAP_VALUE(MyMapValue);
#define CEL_IMPLEMENT_MAP_VALUE(map_value) \
  CEL_INTERNAL_IMPLEMENT_VALUE(Map, map_value)

namespace base_internal {

template <>
struct ValueTraits<MapValue> {
  using type = MapValue;

  using type_type = MapType;

  using underlying_type = void;

  static std::string DebugString(const type& value) {
    return value.DebugString();
  }

  static Handle<type> Wrap(ValueFactory& value_factory, Handle<type> value) {
    static_cast<void>(value_factory);
    return value;
  }

  static Handle<type> Unwrap(Handle<type> value) { return value; }
};

}  // namespace base_internal

}  // namespace cel

#endif  // THIRD_PARTY_CEL_CPP_BASE_VALUES_MAP_VALUE_H_
