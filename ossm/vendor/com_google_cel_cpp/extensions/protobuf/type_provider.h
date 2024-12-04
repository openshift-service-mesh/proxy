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

#ifndef THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_TYPE_PROVIDER_H_
#define THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_TYPE_PROVIDER_H_

#include "absl/base/attributes.h"
#include "absl/log/die_if_null.h"
#include "absl/types/optional.h"
#include "base/type_provider.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/message.h"

namespace cel::extensions {

class ProtoTypeProvider final : public TypeProvider {
 public:
  ProtoTypeProvider()
      : ProtoTypeProvider(google::protobuf::DescriptorPool::generated_pool(),
                          google::protobuf::MessageFactory::generated_factory()) {}

  explicit ProtoTypeProvider(
      ABSL_ATTRIBUTE_LIFETIME_BOUND const google::protobuf::DescriptorPool* pool)
      : pool_(ABSL_DIE_IF_NULL(pool)),  // Crash OK
        dynamic_factory_(pool),
        factory_(&dynamic_factory_.value()) {}

  ProtoTypeProvider(
      ABSL_ATTRIBUTE_LIFETIME_BOUND const google::protobuf::DescriptorPool* pool,
      ABSL_ATTRIBUTE_LIFETIME_BOUND google::protobuf::MessageFactory* factory)
      : pool_(ABSL_DIE_IF_NULL(pool)),  // Crash OK
        dynamic_factory_(absl::nullopt),
        factory_(ABSL_DIE_IF_NULL(factory)) {}  // Crash OK

  absl::StatusOr<absl::optional<Handle<Type>>> ProvideType(
      TypeFactory& type_factory, absl::string_view name) const override;

 private:
  const google::protobuf::DescriptorPool* const pool_;
  absl::optional<google::protobuf::DynamicMessageFactory> dynamic_factory_;
  google::protobuf::MessageFactory* const factory_;
};

}  // namespace cel::extensions

#endif  // THIRD_PARTY_CEL_CPP_EXTENSIONS_PROTOBUF_TYPE_PROVIDER_H_
