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

#include "eval/public/structs/legacy_type_provider.h"

#include <optional>
#include <string>

#include "absl/status/status_matchers.h"
#include "absl/strings/string_view.h"
#include "common/type.h"
#include "eval/public/structs/legacy_type_info_apis.h"
#include "internal/testing.h"

namespace google::api::expr::runtime {
namespace {

using ::absl_testing::IsOk;

class LegacyTypeProviderTestEmpty : public LegacyTypeProvider {
 public:
  absl::optional<LegacyTypeAdapter> ProvideLegacyType(
      absl::string_view name) const override {
    return std::nullopt;
  }
};

class LegacyTypeInfoApisEmpty : public LegacyTypeInfoApis {
 public:
  std::string DebugString(
      const MessageWrapper& wrapped_message) const override {
    return "";
  }
  absl::string_view GetTypename(
      const MessageWrapper& wrapped_message) const override {
    return test_string_;
  }
  const LegacyTypeAccessApis* GetAccessApis(
      const MessageWrapper& wrapped_message) const override {
    return nullptr;
  }
  absl::optional<FieldDescription> FindFieldByName(
      absl::string_view name) const override {
    if (name == "field1") {
      return FieldDescription{1, "field1"};
    }
    return absl::nullopt;
  }

 private:
  const std::string test_string_ = "test";
};

class LegacyTypeProviderTestImpl : public LegacyTypeProvider {
 public:
  explicit LegacyTypeProviderTestImpl(const LegacyTypeInfoApis* test_type_info)
      : test_type_info_(test_type_info) {}
  absl::optional<LegacyTypeAdapter> ProvideLegacyType(
      absl::string_view name) const override {
    if (name == "test") {
      return LegacyTypeAdapter(nullptr, nullptr);
    }
    return std::nullopt;
  }
  absl::optional<const LegacyTypeInfoApis*> ProvideLegacyTypeInfo(
      absl::string_view name) const override {
    if (name == "test") {
      return test_type_info_;
    }
    return std::nullopt;
  }

 private:
  const LegacyTypeInfoApis* test_type_info_ = nullptr;
};

TEST(LegacyTypeProviderTest, EmptyTypeProviderHasProvideTypeInfo) {
  LegacyTypeProviderTestEmpty provider;
  EXPECT_EQ(provider.ProvideLegacyType("test"), std::nullopt);
  EXPECT_EQ(provider.ProvideLegacyTypeInfo("test"), std::nullopt);
}

TEST(LegacyTypeProviderTest, NonEmptyTypeProviderProvidesSomeTypes) {
  LegacyTypeInfoApisEmpty test_type_info;
  LegacyTypeProviderTestImpl provider(&test_type_info);
  EXPECT_TRUE(provider.ProvideLegacyType("test").has_value());
  EXPECT_TRUE(provider.ProvideLegacyTypeInfo("test").has_value());
  EXPECT_EQ(provider.ProvideLegacyType("other"), std::nullopt);
  EXPECT_EQ(provider.ProvideLegacyTypeInfo("other"), std::nullopt);
}

TEST(LegacyTypeProviderTest, FindStructTypeFieldByName) {
  LegacyTypeInfoApisEmpty test_type_info;
  LegacyTypeProviderTestImpl provider(&test_type_info);

  ASSERT_OK_AND_ASSIGN(absl::optional<cel::StructTypeField> field,
                       provider.FindStructTypeFieldByName("test", "field1"));
  ASSERT_TRUE(field.has_value());
  EXPECT_EQ(field->name(), "field1");
  EXPECT_EQ(field->number(), 1);
  EXPECT_EQ(field->GetType(), cel::DynType());

  ASSERT_OK_AND_ASSIGN(
      absl::optional<cel::StructTypeField> not_found_field,
      provider.FindStructTypeFieldByName("test", "unknown_field"));
  EXPECT_FALSE(not_found_field.has_value());
}

}  // namespace
}  // namespace google::api::expr::runtime
