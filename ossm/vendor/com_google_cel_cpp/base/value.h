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

#ifndef THIRD_PARTY_CEL_CPP_BASE_VALUE_H_
#define THIRD_PARTY_CEL_CPP_BASE_VALUE_H_

#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/base/optimization.h"
#include "absl/status/statusor.h"
#include "base/handle.h"
#include "base/internal/data.h"
#include "base/internal/value.h"  // IWYU pragma: export
#include "base/kind.h"
#include "base/type.h"
#include "base/types/null_type.h"
#include "common/any.h"
#include "common/json.h"
#include "internal/casts.h"  // IWYU pragma: keep

namespace cel {

class Value;
class ErrorValue;
class BytesValue;
class StringValue;
class EnumValue;
class StructValue;
class ListValue;
class MapValue;
class TypeValue;
class UnknownValue;
class OpaqueValue;
class ValueFactory;

// A representation of a CEL value that enables reflection and introspection of
// values.
class Value : public base_internal::Data {
 public:
  static bool Is(const Value& value ABSL_ATTRIBUTE_UNUSED) { return true; }

  static const Value& Cast(const Value& value) { return value; }

  // Returns the kind of the value. This is equivalent to `type().kind()` but
  // faster in many scenarios. As such it should be preferred when only the kind
  // is required.
  ValueKind kind() const {
    return KindToValueKind(base_internal::Metadata::Kind(*this));
  }

  // Returns the type of the value. If you only need the kind, prefer `kind()`.
  Handle<Type> type() const;

  std::string DebugString() const;

  absl::StatusOr<Any> ConvertToAny(ValueFactory& value_factory) const;

  absl::StatusOr<Json> ConvertToJson(ValueFactory& value_factory) const;

  // Attempts to convert the value to the specified type. This follows language
  // rules and adheres to type conversion per the specification. The resulting
  // value will either be an appropriate instance of type, an error value, or an
  // unknown value.
  absl::StatusOr<Handle<Value>> ConvertToType(ValueFactory& value_factory,
                                              const Handle<Type>& type) const;

  template <typename T>
  bool Is() const {
    static_assert(!std::is_const_v<T>, "T must not be const");
    static_assert(!std::is_volatile_v<T>, "T must not be volatile");
    static_assert(!std::is_pointer_v<T>, "T must not be a pointer");
    static_assert(!std::is_reference_v<T>, "T must not be a reference");
    static_assert(std::is_base_of_v<Value, T>, "T must be derived from Value");
    return T::Is(*this);
  }

  template <typename T>
  const T& As() const {
    static_assert(!std::is_const_v<T>, "T must not be const");
    static_assert(!std::is_volatile_v<T>, "T must not be volatile");
    static_assert(!std::is_pointer_v<T>, "T must not be a pointer");
    static_assert(!std::is_reference_v<T>, "T must not be a reference");
    static_assert(std::is_base_of_v<Value, T>, "T must be derived from Value");
    return T::Cast(*this);
  }

  absl::StatusOr<Handle<Value>> Equals(ValueFactory& value_factory,
                                       const Value& other) const;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const Value& value) {
    sink.Append(value.DebugString());
  }

 private:
  friend class ErrorValue;
  friend class BytesValue;
  friend class StringValue;
  friend class EnumValue;
  friend class StructValue;
  friend class ListValue;
  friend class MapValue;
  friend class TypeValue;
  friend class UnknownValue;
  friend class OpaqueValue;
  friend class base_internal::ValueHandle;
  template <typename T, typename U>
  friend class base_internal::SimpleValue;

  // Determines whether a value with type `from` can be implicitly converted to
  // type `to`. If `from` is dyn then `to` must also be dyn, otherwise `to` must
  // be the same as `from` or `to` must be dyn.
  static bool IsRuntimeConvertible(const Type& from, const Type& to);

  Value() = default;
  Value(const Value&) = default;
  Value(Value&&) = default;
  Value& operator=(const Value&) = default;
  Value& operator=(Value&&) = default;
};

}  // namespace cel

// -----------------------------------------------------------------------------
// Internal implementation details.

namespace cel {

namespace base_internal {

class ValueHandle;

class ValueMetadata final {
 public:
  ValueMetadata() = delete;

  static void Ref(const Value& value) { Metadata::Ref(value); }

  static void Unref(const Value& value);

  static bool IsReferenceCounted(const Value& value) {
    return Metadata::IsReferenceCounted(value);
  }
};

class ValueHandle final {
 public:
  using base_type = Value;

  ValueHandle() = default;

  template <typename T, typename... Args>
  explicit ValueHandle(InPlaceStoredInline<T>, Args&&... args) {
    data_.ConstructInline<T>(std::forward<Args>(args)...);
  }

  explicit ValueHandle(InPlaceArenaAllocated, Value& arg) {
    data_.ConstructArenaAllocated(arg);
  }

  explicit ValueHandle(InPlaceReferenceCounted, Value& arg) {
    data_.ConstructReferenceCounted(arg);
  }

  ValueHandle(const ValueHandle& other) { CopyFrom(other); }

  ValueHandle(ValueHandle&& other) { MoveFrom(other); }

  ~ValueHandle() { Destruct(); }

  ValueHandle& operator=(const ValueHandle& other) {
    if (ABSL_PREDICT_TRUE(this != &other)) {
      CopyAssign(other);
    }
    return *this;
  }

  ValueHandle& operator=(ValueHandle&& other) {
    if (ABSL_PREDICT_TRUE(this != &other)) {
      MoveAssign(other);
    }
    return *this;
  }

  Value* get() const { return static_cast<Value*>(data_.get()); }

  explicit operator bool() const { return !data_.IsNull(); }

  bool Equals(const ValueHandle& other) const;

 private:
  friend class ValueMetadata;

  static bool Equals(const Value& lhs, const Value& rhs, ValueKind kind);

  void CopyFrom(const ValueHandle& other);

  void MoveFrom(ValueHandle& other);

  void CopyAssign(const ValueHandle& other);

  void MoveAssign(ValueHandle& other);

  void Ref() const { data_.Ref(); }

  void Unref() const {
    if (data_.Unref()) {
      Delete();
    }
  }

  void Destruct();

  void Delete() const;

  static void Delete(ValueKind kind, const Value& value);

  AnyValue data_;
};

inline bool operator==(const ValueHandle& lhs, const ValueHandle& rhs) {
  return lhs.Equals(rhs);
}

inline bool operator!=(const ValueHandle& lhs, const ValueHandle& rhs) {
  return !operator==(lhs, rhs);
}

// Specialization for Value providing the implementation to `Handle`.
template <>
struct HandleTraits<Value> {
  using handle_type = ValueHandle;
};

// Partial specialization for `Handle` for all classes derived from Value.
template <typename T>
struct HandleTraits<T, std::enable_if_t<(std::is_base_of_v<Value, T> &&
                                         !std::is_same_v<Value, T>)>>
    final : public HandleTraits<Value> {};

template <typename T, typename U>
class SimpleValue : public Value, InlineData {
 public:
  static constexpr ValueKind kKind = static_cast<ValueKind>(T::kKind);

  static bool Is(const Value& value) { return value.kind() == kKind; }

  explicit SimpleValue(U value) : InlineData(kMetadata), value_(value) {}

  SimpleValue(const SimpleValue&) = default;
  SimpleValue(SimpleValue&&) = default;
  SimpleValue& operator=(const SimpleValue&) = default;
  SimpleValue& operator=(SimpleValue&&) = default;

  constexpr ValueKind kind() const { return kKind; }

  const Handle<T>& type() const { return T::Get(); }

  constexpr U NativeValue() const { return value_; }

  using Value::Is;

 private:
  friend class ValueHandle;

  static constexpr uintptr_t kMetadata =
      kStoredInline |
      (std::conjunction_v<std::is_trivially_copyable<U>,
                          std::is_trivially_destructible<U>>
           ? kTrivial
           : 0) |
      (static_cast<uintptr_t>(kKind) << kKindShift);

  U value_;
};

template <>
class SimpleValue<NullType, void> : public Value, InlineData {
 public:
  static constexpr ValueKind kKind = ValueKind::kNullType;

  static bool Is(const Value& value) { return value.kind() == kKind; }

  constexpr SimpleValue() : InlineData(kMetadata) {}

  SimpleValue(const SimpleValue&) = default;
  SimpleValue(SimpleValue&&) = default;
  SimpleValue& operator=(const SimpleValue&) = default;
  SimpleValue& operator=(SimpleValue&&) = default;

  constexpr ValueKind kind() const { return kKind; }

  const Handle<NullType>& type() const { return NullType::Get(); }

  using Value::Is;

 private:
  friend class ValueHandle;

  static constexpr uintptr_t kMetadata =
      kStoredInline | kTrivial | (static_cast<uintptr_t>(kKind) << kKindShift);
};

template <>
struct ValueTraits<Value> {
  using type = Value;

  using type_type = Type;

  using underlying_type = void;

  static std::string DebugString(const Value& value) {
    return value.DebugString();
  }
};

}  // namespace base_internal

CEL_INTERNAL_VALUE_DECL(Value);

}  // namespace cel

#define CEL_INTERNAL_SIMPLE_VALUE_STANDALONES(value_class)       \
  static_assert(std::is_trivially_copyable_v<value_class>,       \
                #value_class " must be trivially copyable");     \
  static_assert(std::is_trivially_destructible_v<value_class>,   \
                #value_class " must be trivially destructible"); \
                                                                 \
  CEL_INTERNAL_VALUE_DECL(value_class)

#define CEL_INTERNAL_SIMPLE_VALUE_MEMBERS(value_class)  \
 private:                                               \
  friend class ValueFactory;                            \
  friend class base_internal::ValueHandle;              \
  template <size_t Size, size_t Align>                  \
  friend struct base_internal::AnyData;                 \
                                                        \
  value_class(const value_class&) = default;            \
  value_class(value_class&&) = default;                 \
  value_class& operator=(const value_class&) = default; \
  value_class& operator=(value_class&&) = default

#endif  // THIRD_PARTY_CEL_CPP_BASE_VALUE_H_
