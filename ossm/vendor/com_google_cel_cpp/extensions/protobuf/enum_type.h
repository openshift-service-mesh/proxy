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

#ifndef THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_ENUM_TYPE_H_
#define THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_ENUM_TYPE_H_

#include "absl/base/attributes.h"
#include "absl/base/nullability.h"
#include "absl/log/die_if_null.h"
#include "base/memory.h"
#include "base/type.h"
#include "base/type_manager.h"
#include "base/types/enum_type.h"
#include "common/native_type.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/generated_enum_reflection.h"
#include "google/protobuf/generated_enum_util.h"

namespace cel::extensions {

class ProtoType;
class ProtoTypeProvider;

class ProtoEnumTypeConstantIterator;

class ProtoEnumType final : public EnumType {
 public:
  static bool Is(const Type& type) {
    return EnumType::Is(type) && cel::base_internal::GetEnumTypeTypeId(
                                     static_cast<const EnumType&>(type)) ==
                                     cel::NativeTypeId::For<ProtoEnumType>();
  }

  using EnumType::Is;

  static const ProtoEnumType& Cast(const Type& type) {
    ABSL_ASSERT(Is(type));
    return static_cast<const ProtoEnumType&>(type);
  }

  absl::string_view name() const override { return descriptor().full_name(); }

  size_t constant_count() const override;

  // Called by FindField.
  absl::StatusOr<absl::optional<Constant>> FindConstantByName(
      absl::string_view name) const override;

  // Called by FindField.
  absl::StatusOr<absl::optional<Constant>> FindConstantByNumber(
      int64_t number) const override;

  absl::StatusOr<absl::Nonnull<std::unique_ptr<ConstantIterator>>>
  NewConstantIterator(MemoryManagerRef memory_manager) const override;

  const google::protobuf::EnumDescriptor& descriptor() const { return *descriptor_; }

 private:
  friend class ProtoEnumTypeConstantIterator;
  friend class ProtoType;
  friend class ProtoTypeProvider;
  friend class cel::MemoryManager;

  // Called by Arena-based memory managers to determine whether we actually need
  // our destructor called.
  CEL_INTERNAL_IS_DESTRUCTOR_SKIPPABLE() {
    // Our destructor is useless, we only hold pointers to protobuf-owned data.
    return true;
  }

  template <typename T>
  static std::enable_if_t<google::protobuf::is_proto_enum<T>::value,
                          absl::StatusOr<Handle<ProtoEnumType>>>
  Resolve(TypeManager& type_manager) {
    return Resolve(type_manager, *google::protobuf::GetEnumDescriptor<T>());
  }

  static absl::StatusOr<Handle<ProtoEnumType>> Resolve(
      TypeManager& type_manager, const google::protobuf::EnumDescriptor& descriptor);

  explicit ProtoEnumType(const google::protobuf::EnumDescriptor* descriptor)
      : descriptor_(ABSL_DIE_IF_NULL(descriptor)) {}  // Crash OK.

  // Called by CEL_IMPLEMENT_STRUCT_TYPE() and Is() to perform type checking.
  NativeTypeId GetNativeTypeId() const override {
    return NativeTypeId::For<ProtoEnumType>();
  }

  const google::protobuf::EnumDescriptor* const descriptor_;
};

}  // namespace cel::extensions

#endif  // THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_ENUM_TYPE_H_
