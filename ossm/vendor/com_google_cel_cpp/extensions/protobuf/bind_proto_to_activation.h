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

#ifndef THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_BIND_PROTO_TO_ACTIVATION_H_
#define THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_BIND_PROTO_TO_ACTIVATION_H_

#include "absl/status/status.h"
#include "base/value_factory.h"
#include "runtime/activation.h"
#include "google/protobuf/message.h"

namespace cel::extensions {

// Option for handling unset fields on the context proto.
enum class BindProtoUnsetFieldBehavior {
  // Bind the message defined default or zero value.
  kBindDefaultValue,
  // Skip binding unset fields, no value is bound for the corresponding
  // variable.
  kSkip
};

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
//
// The input message is not copied, it must remain valid as long as the
// activation.
absl::Status BindProtoToActivation(
    const google::protobuf::Message& context, ValueFactory& value_factory,
    Activation& activation,
    BindProtoUnsetFieldBehavior unset_field_behavior =
        BindProtoUnsetFieldBehavior::kSkip);

}  // namespace cel::extensions

#endif  // THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_BIND_PROTO_TO_ACTIVATION_H_
