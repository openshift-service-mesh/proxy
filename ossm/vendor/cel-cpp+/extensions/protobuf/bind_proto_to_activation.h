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

#include "absl/base/attributes.h"
#include "runtime/bind_proto_to_activation.h"

namespace cel::extensions {

using BindProtoUnsetFieldBehavior ABSL_DEPRECATED(
    "Use cel::BindProtoUnsetFieldBehavior instead") =
    ::cel::BindProtoUnsetFieldBehavior;

using ::cel::BindProtoToActivation;
using ::cel::BindProtoViewToActivation;

namespace protobuf_internal {

using ::cel::runtime_internal::BindProtoToActivation;

}  // namespace protobuf_internal

}  // namespace cel::extensions

#endif  // THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_BIND_PROTO_TO_ACTIVATION_H_
