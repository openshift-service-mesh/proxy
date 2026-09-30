// Copyright 2024 Google LLC
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

#ifndef THIRD_PARTY_CEL_CPP_RUNTIME_INTERNAL_RUNTIME_ENV_TESTING_H_
#define THIRD_PARTY_CEL_CPP_RUNTIME_INTERNAL_RUNTIME_ENV_TESTING_H_

#include <memory>

#include "absl/base/nullability.h"
#include "absl/log/absl_check.h"
#include "absl/log/die_if_null.h"
#include "internal/testing_descriptor_pool.h"
#include "internal/testing_message_factory.h"
#include "runtime/internal/runtime_env.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"

namespace cel::runtime_internal {

absl_nonnull std::shared_ptr<RuntimeEnv> NewTestingRuntimeEnv();

template <typename T>
const google::protobuf::Descriptor* absl_nonnull GetTestingEnvDescriptor() {
  const google::protobuf::Descriptor* descriptor =
      internal::GetTestingDescriptorPool()->FindMessageTypeByName(
          T::descriptor()->full_name());
  ABSL_CHECK(descriptor != nullptr)
      << "Could not find CEL test env descriptor for type "
      << T::descriptor()->full_name();
  return descriptor;
}

template <typename T>
google::protobuf::Message* absl_nonnull MakeTestingEnvDynamicProto(
    const T& in, google::protobuf::Arena* absl_nonnull arena) {
  const google::protobuf::Descriptor* descriptor = GetTestingEnvDescriptor<T>();
  google::protobuf::Message* out =
      ABSL_DIE_IF_NULL(
          internal::GetTestingMessageFactory()->GetPrototype(descriptor))
          ->New(arena);

  ABSL_CHECK(out->MergeFromString(in.SerializeAsString()));
  return out;
}

}  // namespace cel::runtime_internal

#endif  // THIRD_PARTY_CEL_CPP_RUNTIME_INTERNAL_RUNTIME_ENV_TESTING_H_
