// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "eval/public/structs/protobuf_descriptor_type_provider.h"

#include <optional>

#include "google/protobuf/wrappers.pb.h"
#include "absl/status/status_matchers.h"
#include "common/type.h"
#include "eval/public/cel_value.h"
#include "eval/public/structs/legacy_type_info_apis.h"
#include "eval/public/testing/matchers.h"
#include "extensions/protobuf/memory_manager.h"
#include "internal/testing.h"
#include "internal/testing_descriptor_pool.h"
#include "internal/testing_message_factory.h"
#include "cel/expr/conformance/proto3/test_all_types.pb.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"

namespace google::api::expr::runtime {
namespace {

using ::absl_testing::IsOk;
using ::cel::expr::conformance::proto3::TestAllTypes;
using ::cel::extensions::ProtoMemoryManager;

TEST(ProtobufDescriptorProvider, Basic) {
  ProtobufDescriptorProvider provider(
      google::protobuf::DescriptorPool::generated_pool(),
      google::protobuf::MessageFactory::generated_factory());
  google::protobuf::Arena arena;
  auto manager = ProtoMemoryManager(&arena);
  auto type_adapter = provider.ProvideLegacyType("google.protobuf.Int64Value");
  std::optional<const LegacyTypeInfoApis*> type_info =
      provider.ProvideLegacyTypeInfo("google.protobuf.Int64Value");

  ASSERT_TRUE(type_adapter.has_value());
  ASSERT_TRUE(type_adapter->mutation_apis() != nullptr);
  ASSERT_TRUE(type_info.has_value());
  ASSERT_TRUE(type_info != nullptr);

  google::protobuf::Int64Value int64_value;
  CelValue::MessageWrapper int64_cel_value(&int64_value, *type_info);
  EXPECT_EQ((*type_info)->GetTypename(int64_cel_value),
            "google.protobuf.Int64Value");

  ASSERT_TRUE(type_adapter->mutation_apis()->DefinesField("value"));
  ASSERT_OK_AND_ASSIGN(CelValue::MessageWrapper::Builder value,
                       type_adapter->mutation_apis()->NewInstance(manager));

  ASSERT_THAT(type_adapter->mutation_apis()->SetField(
                  "value", CelValue::CreateInt64(10), manager, value),
              IsOk());

  ASSERT_OK_AND_ASSIGN(
      CelValue adapted,
      type_adapter->mutation_apis()->AdaptFromWellKnownType(manager, value));

  EXPECT_THAT(adapted, test::IsCelInt64(10));
}

// This is an implementation detail, but testing for coverage.
TEST(ProtobufDescriptorProvider, MemoizesAdapters) {
  ProtobufDescriptorProvider provider(
      google::protobuf::DescriptorPool::generated_pool(),
      google::protobuf::MessageFactory::generated_factory());
  auto type_adapter = provider.ProvideLegacyType("google.protobuf.Int64Value");

  ASSERT_TRUE(type_adapter.has_value());
  ASSERT_TRUE(type_adapter->mutation_apis() != nullptr);

  auto type_adapter2 = provider.ProvideLegacyType("google.protobuf.Int64Value");
  ASSERT_TRUE(type_adapter2.has_value());

  EXPECT_EQ(type_adapter->mutation_apis(), type_adapter2->mutation_apis());
  EXPECT_EQ(type_adapter->access_apis(), type_adapter2->access_apis());
}

TEST(ProtobufDescriptorProvider, NotFound) {
  ProtobufDescriptorProvider provider(
      google::protobuf::DescriptorPool::generated_pool(),
      google::protobuf::MessageFactory::generated_factory());
  auto type_adapter = provider.ProvideLegacyType("UnknownType");
  auto type_info = provider.ProvideLegacyTypeInfo("UnknownType");

  ASSERT_FALSE(type_adapter.has_value());
  ASSERT_FALSE(type_info.has_value());
}

TEST(ProtobufDescriptorProvider, FindType) {
  ProtobufDescriptorProvider provider(
      cel::internal::GetTestingDescriptorPool(),
      cel::internal::GetTestingMessageFactory());
  ASSERT_OK_AND_ASSIGN(std::optional<cel::Type> wrapper_type,
                       provider.FindType("google.protobuf.Int64Value"));
  ASSERT_TRUE(wrapper_type.has_value());
  EXPECT_TRUE(wrapper_type->Is<cel::IntWrapperType>());
  EXPECT_EQ(wrapper_type->name(), "google.protobuf.Int64Value");

  ASSERT_OK_AND_ASSIGN(
      std::optional<cel::Type> msg_type,
      provider.FindType("cel.expr.conformance.proto3.TestAllTypes"));
  ASSERT_TRUE(msg_type.has_value());
  EXPECT_TRUE(msg_type->Is<cel::MessageType>());
  EXPECT_EQ(msg_type->name(), "cel.expr.conformance.proto3.TestAllTypes");
}

TEST(ProtobufDescriptorProvider, FindStructTypeFieldByName) {
  ProtobufDescriptorProvider provider(
      google::protobuf::DescriptorPool::generated_pool(),
      google::protobuf::MessageFactory::generated_factory());
  ASSERT_OK_AND_ASSIGN(std::optional<cel::StructTypeField> field,
                       provider.FindStructTypeFieldByName(
                           "google.protobuf.Int64Value", "value"));
  ASSERT_TRUE(field.has_value());
  EXPECT_EQ(field->name(), "value");
  EXPECT_EQ(field->number(), 1);
  EXPECT_EQ(field->GetType(), cel::IntType());
}

TEST(ProtobufDescriptorProvider, FindTypeNotFound) {
  ProtobufDescriptorProvider provider(
      google::protobuf::DescriptorPool::generated_pool(),
      google::protobuf::MessageFactory::generated_factory());
  ASSERT_OK_AND_ASSIGN(std::optional<cel::Type> type,
                       provider.FindType("UnknownType"));
  EXPECT_FALSE(type.has_value());
}

TEST(ProtobufDescriptorProvider, FindStructTypeFieldByNameNotFound) {
  ProtobufDescriptorProvider provider(
      google::protobuf::DescriptorPool::generated_pool(),
      google::protobuf::MessageFactory::generated_factory());
  ASSERT_OK_AND_ASSIGN(std::optional<cel::StructTypeField> field,
                       provider.FindStructTypeFieldByName(
                           "google.protobuf.Int64Value", "unknown_field"));
  EXPECT_FALSE(field.has_value());

  ASSERT_OK_AND_ASSIGN(
      std::optional<cel::StructTypeField> field2,
      provider.FindStructTypeFieldByName("UnknownType", "value"));
  EXPECT_FALSE(field2.has_value());
}

}  // namespace
}  // namespace google::api::expr::runtime
