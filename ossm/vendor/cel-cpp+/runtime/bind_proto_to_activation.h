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

#ifndef THIRD_PARTY_CEL_CPP_RUNTIME_BIND_PROTO_TO_ACTIVATION_H_
#define THIRD_PARTY_CEL_CPP_RUNTIME_BIND_PROTO_TO_ACTIVATION_H_

#include <type_traits>

#include "absl/base/nullability.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "common/value.h"
#include "runtime/activation.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"

namespace cel {

// Option for handling unset fields on the context proto.
enum class BindProtoUnsetFieldBehavior {
  // Bind the message defined default or zero value.
  kBindDefaultValue,
  // Skip binding unset fields, no value is bound for the corresponding
  // variable.
  kSkip
};

namespace runtime_internal {

// Implements binding provided the context message has already
// been adapted to a suitable struct value.
absl::Status BindProtoToActivation(
    const google::protobuf::Descriptor& descriptor, const StructValue& struct_value,
    BindProtoUnsetFieldBehavior unset_field_behavior,
    const google::protobuf::DescriptorPool* absl_nonnull descriptor_pool,
    google::protobuf::MessageFactory* absl_nonnull message_factory,
    google::protobuf::Arena* absl_nonnull arena, Activation* absl_nonnull activation);

template <bool kBorrow, typename T>
absl::Status BindProtoToActivationImpl(
    const T& context, BindProtoUnsetFieldBehavior unset_field_behavior,
    const google::protobuf::DescriptorPool* absl_nonnull descriptor_pool,
    google::protobuf::MessageFactory* absl_nonnull message_factory,
    google::protobuf::Arena* absl_nonnull arena, Activation* absl_nonnull activation) {
  static_assert(std::is_base_of_v<google::protobuf::Message, T>);

  Value parent;
  if constexpr (kBorrow) {
    parent = Value::WrapMessageUnsafe(&context, descriptor_pool,
                                      message_factory, arena);
  } else {
    parent =
        Value::FromMessage(context, descriptor_pool, message_factory, arena);
  }

  if (!parent.IsStruct()) {
    return absl::InvalidArgumentError(
        absl::StrCat("context is a well-known type: ", context.GetTypeName()));
  }
  StructValue struct_value = parent.GetStruct();

  const google::protobuf::Descriptor* descriptor = context.GetDescriptor();
  ABSL_DCHECK(descriptor != nullptr);
  if (descriptor == nullptr) {
    // Generally not possible, but don't crash in case of a misbehaving
    // implementation in normal builds.
    return absl::InvalidArgumentError(
        absl::StrCat("context missing descriptor: ", context.GetTypeName()));
  }

  return BindProtoToActivation(*descriptor, struct_value, unset_field_behavior,
                               descriptor_pool, message_factory, arena,
                               activation);
}

}  // namespace runtime_internal

// Utility method, that takes a protobuf Message and interprets it as a
// namespace, binding its fields to Activation. This is often referred to as a
// context message.
//
// Field names and values become respective names and values of parameters
// bound to the Activation object.
// Example:
// Assume we have a protobuf message of type:
// message Person {
//   int age = 1;
//   string name = 2;
// }
//
// The sample code snippet will look as follows:
//
//   Person person;
//   person.set_name("John Doe");
//   person.age(42);
//
//   CEL_RETURN_IF_ERROR(BindProtoToActivation(person, value_factory,
//   activation));
//
// After this snippet, activation will have two parameters bound:
//  "name", with string value of "John Doe"
//  "age", with int value of 42.
//
// The default behavior for unset fields is to skip them. E.g. if the name field
// is not set on the Person message, it will not be bound in to the activation.
// BindProtoUnsetFieldBehavior::kBindDefault, will bind the cc proto api default
// for the field (either an explicit default value or a type specific default).
//
// For repeated fields, an unset field is bound as an empty list.
template <typename T>
absl::Status BindProtoToActivation(
    const T& context, BindProtoUnsetFieldBehavior unset_field_behavior,
    const google::protobuf::DescriptorPool* absl_nonnull descriptor_pool,
    google::protobuf::MessageFactory* absl_nonnull message_factory,
    google::protobuf::Arena* absl_nonnull arena, Activation* absl_nonnull activation) {
  return runtime_internal::BindProtoToActivationImpl<false>(
      context, unset_field_behavior, descriptor_pool, message_factory, arena,
      activation);
}

template <typename T>
absl::Status BindProtoToActivation(
    const T& context,
    const google::protobuf::DescriptorPool* absl_nonnull descriptor_pool,
    google::protobuf::MessageFactory* absl_nonnull message_factory,
    google::protobuf::Arena* absl_nonnull arena, Activation* absl_nonnull activation) {
  return BindProtoToActivation(context, BindProtoUnsetFieldBehavior::kSkip,
                               descriptor_pool, message_factory, arena,
                               activation);
}

// Like `BindProtoToActivation`, but uses `Value::WrapMessageUnsafe` to borrow
// from `context` rather than copying fields to `arena`.
//
// Requires the caller to keep the context message valid as long as the
// activation or any derived value.
template <typename T>
absl::Status BindProtoViewToActivation(
    const T& context, BindProtoUnsetFieldBehavior unset_field_behavior,
    const google::protobuf::DescriptorPool* absl_nonnull descriptor_pool,
    google::protobuf::MessageFactory* absl_nonnull message_factory,
    google::protobuf::Arena* absl_nonnull arena, Activation* absl_nonnull activation) {
  return runtime_internal::BindProtoToActivationImpl<true>(
      context, unset_field_behavior, descriptor_pool, message_factory, arena,
      activation);
}

template <typename T>
absl::Status BindProtoViewToActivation(
    const T& context,
    const google::protobuf::DescriptorPool* absl_nonnull descriptor_pool,
    google::protobuf::MessageFactory* absl_nonnull message_factory,
    google::protobuf::Arena* absl_nonnull arena, Activation* absl_nonnull activation) {
  return BindProtoViewToActivation(context, BindProtoUnsetFieldBehavior::kSkip,
                                   descriptor_pool, message_factory, arena,
                                   activation);
}

}  // namespace cel

#endif  // THIRD_PARTY_CEL_CPP_RUNTIME_BIND_PROTO_TO_ACTIVATION_H_
