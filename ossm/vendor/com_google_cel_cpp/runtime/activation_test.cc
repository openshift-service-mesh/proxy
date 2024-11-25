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

#include "runtime/activation.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "base/attribute.h"
#include "base/function.h"
#include "base/function_descriptor.h"
#include "base/handle.h"
#include "base/memory.h"
#include "base/type_factory.h"
#include "base/type_manager.h"
#include "base/type_provider.h"
#include "base/value.h"
#include "base/value_factory.h"
#include "base/values/int_value.h"
#include "base/values/null_value.h"
#include "internal/status_macros.h"
#include "internal/testing.h"

namespace cel {
namespace {
using testing::ElementsAre;
using testing::IsEmpty;
using testing::Optional;
using testing::Truly;
using testing::UnorderedElementsAre;
using cel::internal::IsOkAndHolds;
using cel::internal::StatusIs;

MATCHER_P(IsIntValue, x, absl::StrCat("is IntValue Handle with value ", x)) {
  const Handle<Value>& handle = arg;

  return handle->Is<IntValue>() && handle.As<IntValue>()->NativeValue() == x;
}

MATCHER_P(AttributePatternMatches, val, "matches AttributePattern") {
  const AttributePattern& pattern = arg;
  const Attribute& expected = val;

  return pattern.IsMatch(expected) == AttributePattern::MatchType::FULL;
}

class FunctionImpl : public cel::Function {
 public:
  FunctionImpl() = default;

  absl::StatusOr<Handle<Value>> Invoke(
      const FunctionEvaluationContext& ctx,
      absl::Span<const Handle<Value>> args) const override {
    return Handle<NullValue>();
  }
};

class ActivationTest : public testing::Test {
 public:
  ActivationTest()
      : type_factory_(MemoryManagerRef::ReferenceCounting()),
        type_manager_(type_factory_, TypeProvider::Builtin()),
        value_factory_(type_manager_) {}

 protected:
  TypeFactory type_factory_;
  TypeManager type_manager_;
  ValueFactory value_factory_;
};

TEST_F(ActivationTest, ValueNotFound) {
  Activation activation;

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(absl::nullopt));
}

TEST_F(ActivationTest, InsertValue) {
  Activation activation;
  EXPECT_TRUE(activation.InsertOrAssignValue(
      "var1", value_factory_.CreateIntValue(42)));

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(Optional(IsIntValue(42))));
}

TEST_F(ActivationTest, InsertValueOverwrite) {
  Activation activation;
  EXPECT_TRUE(activation.InsertOrAssignValue(
      "var1", value_factory_.CreateIntValue(42)));
  EXPECT_FALSE(
      activation.InsertOrAssignValue("var1", value_factory_.CreateIntValue(0)));

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(Optional(IsIntValue(0))));
}

TEST_F(ActivationTest, InsertProvider) {
  Activation activation;

  EXPECT_TRUE(activation.InsertOrAssignValueProvider(
      "var1", [](ValueFactory& factory, absl::string_view name) {
        return factory.CreateIntValue(42);
      }));

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(Optional(IsIntValue(42))));
}

TEST_F(ActivationTest, InsertProviderForwardsNotFound) {
  Activation activation;

  EXPECT_TRUE(activation.InsertOrAssignValueProvider(
      "var1", [](ValueFactory& factory, absl::string_view name) {
        return absl::nullopt;
      }));

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(absl::nullopt));
}

TEST_F(ActivationTest, InsertProviderForwardsStatus) {
  Activation activation;

  EXPECT_TRUE(activation.InsertOrAssignValueProvider(
      "var1", [](ValueFactory& factory, absl::string_view name) {
        return absl::InternalError("test");
      }));

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              StatusIs(absl::StatusCode::kInternal, "test"));
}

TEST_F(ActivationTest, ProviderMemoized) {
  Activation activation;
  int call_count = 0;

  EXPECT_TRUE(activation.InsertOrAssignValueProvider(
      "var1", [&call_count](ValueFactory& factory, absl::string_view name) {
        call_count++;
        return factory.CreateIntValue(42);
      }));

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(Optional(IsIntValue(42))));
  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(Optional(IsIntValue(42))));
  EXPECT_EQ(call_count, 1);
}

TEST_F(ActivationTest, InsertProviderOverwrite) {
  Activation activation;

  EXPECT_TRUE(activation.InsertOrAssignValueProvider(
      "var1", [](ValueFactory& factory, absl::string_view name) {
        return factory.CreateIntValue(42);
      }));
  EXPECT_FALSE(activation.InsertOrAssignValueProvider(
      "var1", [](ValueFactory& factory, absl::string_view name) {
        return factory.CreateIntValue(0);
      }));

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(Optional(IsIntValue(0))));
}

TEST_F(ActivationTest, ValuesAndProvidersShareNamespace) {
  Activation activation;
  bool called = false;

  EXPECT_TRUE(activation.InsertOrAssignValue(
      "var1", value_factory_.CreateIntValue(41)));
  EXPECT_TRUE(activation.InsertOrAssignValue(
      "var2", value_factory_.CreateIntValue(41)));

  EXPECT_FALSE(activation.InsertOrAssignValueProvider(
      "var1", [&called](ValueFactory& factory, absl::string_view name) {
        called = true;
        return factory.CreateIntValue(42);
      }));

  EXPECT_THAT(activation.FindVariable(value_factory_, "var1"),
              IsOkAndHolds(Optional(IsIntValue(42))));
  EXPECT_THAT(activation.FindVariable(value_factory_, "var2"),
              IsOkAndHolds(Optional(IsIntValue(41))));
  EXPECT_TRUE(called);
}

TEST_F(ActivationTest, SetUnknownAttributes) {
  Activation activation;

  activation.SetUnknownPatterns(
      {AttributePattern("var1",
                        {AttributeQualifierPattern::OfString("field1")}),
       AttributePattern("var1",
                        {AttributeQualifierPattern::OfString("field2")})});

  EXPECT_THAT(
      activation.GetUnknownAttributes(),
      ElementsAre(AttributePatternMatches(Attribute(
                      "var1", {AttributeQualifier::OfString("field1")})),
                  AttributePatternMatches(Attribute(
                      "var1", {AttributeQualifier::OfString("field2")}))));
}

TEST_F(ActivationTest, ClearUnknownAttributes) {
  Activation activation;

  activation.SetUnknownPatterns(
      {AttributePattern("var1",
                        {AttributeQualifierPattern::OfString("field1")}),
       AttributePattern("var1",
                        {AttributeQualifierPattern::OfString("field2")})});
  activation.SetUnknownPatterns({});

  EXPECT_THAT(activation.GetUnknownAttributes(), IsEmpty());
}

TEST_F(ActivationTest, SetMissingAttributes) {
  Activation activation;

  activation.SetMissingPatterns(
      {AttributePattern("var1",
                        {AttributeQualifierPattern::OfString("field1")}),
       AttributePattern("var1",
                        {AttributeQualifierPattern::OfString("field2")})});

  EXPECT_THAT(
      activation.GetMissingAttributes(),
      ElementsAre(AttributePatternMatches(Attribute(
                      "var1", {AttributeQualifier::OfString("field1")})),
                  AttributePatternMatches(Attribute(
                      "var1", {AttributeQualifier::OfString("field2")}))));
}

TEST_F(ActivationTest, ClearMissingAttributes) {
  Activation activation;

  activation.SetMissingPatterns(
      {AttributePattern("var1",
                        {AttributeQualifierPattern::OfString("field1")}),
       AttributePattern("var1",
                        {AttributeQualifierPattern::OfString("field2")})});
  activation.SetMissingPatterns({});

  EXPECT_THAT(activation.GetMissingAttributes(), IsEmpty());
}

TEST_F(ActivationTest, InsertFunctionOk) {
  Activation activation;

  EXPECT_TRUE(
      activation.InsertFunction(FunctionDescriptor("Fn", false, {Kind::kUint}),
                                std::make_unique<FunctionImpl>()));
  EXPECT_TRUE(
      activation.InsertFunction(FunctionDescriptor("Fn", false, {Kind::kInt}),
                                std::make_unique<FunctionImpl>()));
  EXPECT_TRUE(
      activation.InsertFunction(FunctionDescriptor("Fn2", false, {Kind::kInt}),
                                std::make_unique<FunctionImpl>()));

  EXPECT_THAT(
      activation.FindFunctionOverloads("Fn"),
      UnorderedElementsAre(
          Truly([](const FunctionOverloadReference& ref) {
            return ref.descriptor.name() == "Fn" &&
                   ref.descriptor.types() == std::vector<Kind>{Kind::kUint};
          }),
          Truly([](const FunctionOverloadReference& ref) {
            return ref.descriptor.name() == "Fn" &&
                   ref.descriptor.types() == std::vector<Kind>{Kind::kInt};
          })))
      << "expected overloads Fn(int), Fn(uint)";
}

TEST_F(ActivationTest, InsertFunctionFails) {
  Activation activation;

  EXPECT_TRUE(
      activation.InsertFunction(FunctionDescriptor("Fn", false, {Kind::kAny}),
                                std::make_unique<FunctionImpl>()));
  EXPECT_FALSE(
      activation.InsertFunction(FunctionDescriptor("Fn", false, {Kind::kInt}),
                                std::make_unique<FunctionImpl>()));

  EXPECT_THAT(activation.FindFunctionOverloads("Fn"),
              ElementsAre(Truly([](const FunctionOverloadReference& ref) {
                return ref.descriptor.name() == "Fn" &&
                       ref.descriptor.types() == std::vector<Kind>{Kind::kAny};
              })))
      << "expected overload Fn(any)";
}

}  // namespace
}  // namespace cel
