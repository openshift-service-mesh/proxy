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

#include "base/values/list_value_builder.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "base/handle.h"
#include "base/memory.h"
#include "base/type_factory.h"
#include "base/type_manager.h"
#include "base/type_provider.h"
#include "base/value_factory.h"
#include "base/values/int_value.h"
#include "base/values/uint_value.h"
#include "internal/testing.h"

namespace cel {
namespace {

using testing::NotNull;
using testing::WhenDynamicCastTo;
using cel::internal::IsOkAndHolds;
using cel::internal::StatusIs;

TEST(ListValueBuilder, Unspecialized) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
  auto list_builder =
      ListValueBuilder<BytesValue>(value_factory, type_factory.GetBytesType());
  list_builder.Reserve(2);
  EXPECT_TRUE(list_builder.IsEmpty());
  auto value = value_factory.GetBytesValue().As<Value>();
  EXPECT_OK(list_builder.Add(value));                          // lvalue
  EXPECT_OK(list_builder.Add(value_factory.GetBytesValue()));  // rvalue
  EXPECT_EQ(list_builder.DebugString(), "[b\"\", b\"\"]");
  ASSERT_OK_AND_ASSIGN(auto list, std::move(list_builder).Build());
  EXPECT_EQ(list->Size(), 2);
  EXPECT_EQ(list->DebugString(), "[b\"\", b\"\"]");
  EXPECT_THAT(list->AnyOf(value_factory,
                          [](const Handle<Value>& v) -> absl::StatusOr<bool> {
                            return v->Is<BytesValue>() &&
                                   v->As<BytesValue>().DebugString() ==
                                       R"(b"")";
                          }),
              IsOkAndHolds(true));
  EXPECT_THAT(list->AnyOf(value_factory,
                          [](const Handle<Value>& v) -> absl::StatusOr<bool> {
                            return v->Is<BytesValue>() &&
                                   v->As<BytesValue>().DebugString() ==
                                       R"(b"1234")";
                          }),
              IsOkAndHolds(false));
  EXPECT_THAT(list->AnyOf(value_factory,
                          [](const Handle<Value>& v) -> absl::StatusOr<bool> {
                            return absl::InternalError("test");
                          }),
              StatusIs(absl::StatusCode::kInternal, "test"));
  ASSERT_OK_AND_ASSIGN(auto element, list->Get(value_factory, 0));
  EXPECT_TRUE(element->Is<BytesValue>());
  EXPECT_TRUE(element.As<BytesValue>()->Equals(value->As<BytesValue>()));
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 1));
  EXPECT_TRUE(element->Is<BytesValue>());
  EXPECT_TRUE(element.As<BytesValue>()->Equals(value->As<BytesValue>()));
}

TEST(ListValueBuilder, Value) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
  auto list_builder =
      ListValueBuilder<Value>(value_factory, type_factory.GetBytesType());
  list_builder.Reserve(2);
  EXPECT_TRUE(list_builder.IsEmpty());
  auto value = value_factory.GetBytesValue().As<Value>();
  EXPECT_OK(list_builder.Add(value));                          // lvalue
  EXPECT_OK(list_builder.Add(value_factory.GetBytesValue()));  // rvalue
  EXPECT_THAT(
      list_builder.Add(value_factory.CreateErrorValue(absl::CancelledError())),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_EQ(list_builder.Size(), 2);
  EXPECT_EQ(list_builder.DebugString(), "[b\"\", b\"\"]");
  ASSERT_OK_AND_ASSIGN(auto list, std::move(list_builder).Build());
  EXPECT_EQ(list->Size(), 2);
  EXPECT_EQ(list->DebugString(), "[b\"\", b\"\"]");
  ASSERT_OK_AND_ASSIGN(auto element, list->Get(value_factory, 0));
  EXPECT_TRUE(element->Is<BytesValue>());
  EXPECT_TRUE(element.As<BytesValue>()->Equals(value->As<BytesValue>()));
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 1));
  EXPECT_TRUE(element->Is<BytesValue>());
  EXPECT_TRUE(element.As<BytesValue>()->Equals(value->As<BytesValue>()));
}

TEST(ListValueBuilder, Bool) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
  auto list_builder =
      ListValueBuilder<BoolValue>(value_factory, type_factory.GetBoolType());
  list_builder.Reserve(3);
  EXPECT_TRUE(list_builder.IsEmpty());
  auto value = value_factory.CreateBoolValue(true).As<Value>();
  EXPECT_OK(list_builder.Add(false));
  EXPECT_OK(list_builder.Add(value));  // lvalue
  EXPECT_OK(list_builder.Add(
      value_factory.CreateBoolValue(false).As<Value>()));  // rvalue
  EXPECT_EQ(list_builder.Size(), 3);
  EXPECT_EQ(list_builder.DebugString(), "[false, true, false]");
  ASSERT_OK_AND_ASSIGN(auto list, std::move(list_builder).Build());
  EXPECT_EQ(list->Size(), 3);
  EXPECT_EQ(list->DebugString(), "[false, true, false]");
  ASSERT_OK_AND_ASSIGN(auto element, list->Get(value_factory, 0));
  EXPECT_TRUE(element->Is<BoolValue>());
  EXPECT_FALSE(element.As<BoolValue>()->NativeValue());
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 1));
  EXPECT_TRUE(element->Is<BoolValue>());
  EXPECT_TRUE(element.As<BoolValue>()->NativeValue());
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 2));
  EXPECT_TRUE(element->Is<BoolValue>());
  EXPECT_FALSE(element.As<BoolValue>()->NativeValue());
}

TEST(ListValueBuilder, Int) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
  auto list_builder =
      ListValueBuilder<IntValue>(value_factory, type_factory.GetIntType());
  list_builder.Reserve(3);
  EXPECT_TRUE(list_builder.IsEmpty());
  auto value = value_factory.CreateIntValue(1).As<Value>();
  EXPECT_OK(list_builder.Add(0));
  EXPECT_OK(list_builder.Add(value));  // lvalue
  EXPECT_OK(
      list_builder.Add(value_factory.CreateIntValue(2).As<Value>()));  // rvalue
  EXPECT_EQ(list_builder.Size(), 3);
  EXPECT_EQ(list_builder.DebugString(), "[0, 1, 2]");
  ASSERT_OK_AND_ASSIGN(auto list, std::move(list_builder).Build());
  EXPECT_EQ(list->Size(), 3);
  EXPECT_EQ(list->DebugString(), "[0, 1, 2]");
  EXPECT_THAT(list->AnyOf(value_factory,
                          [](const Handle<Value>& v) -> absl::StatusOr<bool> {
                            return v->Is<IntValue>() &&
                                   v->As<IntValue>().NativeValue() > 2;
                          }),
              IsOkAndHolds(false));
  EXPECT_THAT(list->AnyOf(value_factory,
                          [](const Handle<Value>& v) -> absl::StatusOr<bool> {
                            return v->Is<IntValue>() &&
                                   v->As<IntValue>().NativeValue() < 2;
                          }),
              IsOkAndHolds(true));
  EXPECT_THAT(list->AnyOf(value_factory,
                          [](const Handle<Value>& v) -> absl::StatusOr<bool> {
                            return absl::InternalError("test");
                          }),
              StatusIs(absl::StatusCode::kInternal, "test"));
  ASSERT_OK_AND_ASSIGN(auto element, list->Get(value_factory, 0));
  EXPECT_TRUE(element->Is<IntValue>());
  EXPECT_EQ(element.As<IntValue>()->NativeValue(), 0);
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 1));
  EXPECT_TRUE(element->Is<IntValue>());
  EXPECT_EQ(element.As<IntValue>()->NativeValue(), 1);
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 2));
  EXPECT_TRUE(element->Is<IntValue>());
  EXPECT_EQ(element.As<IntValue>()->NativeValue(), 2);
}

TEST(ListValueBuilder, Uint) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
  auto list_builder =
      ListValueBuilder<UintValue>(value_factory, type_factory.GetUintType());
  list_builder.Reserve(3);
  EXPECT_TRUE(list_builder.IsEmpty());
  auto value = value_factory.CreateUintValue(1).As<Value>();
  EXPECT_OK(list_builder.Add(0));
  EXPECT_OK(list_builder.Add(value));  // lvalue
  EXPECT_OK(list_builder.Add(
      value_factory.CreateUintValue(2).As<Value>()));  // rvalue
  EXPECT_EQ(list_builder.Size(), 3);
  EXPECT_EQ(list_builder.DebugString(), "[0u, 1u, 2u]");
  ASSERT_OK_AND_ASSIGN(auto list, std::move(list_builder).Build());
  EXPECT_EQ(list->Size(), 3);
  EXPECT_EQ(list->DebugString(), "[0u, 1u, 2u]");
  ASSERT_OK_AND_ASSIGN(auto element, list->Get(value_factory, 0));
  EXPECT_TRUE(element->Is<UintValue>());
  EXPECT_EQ(element.As<UintValue>()->NativeValue(), 0);
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 1));
  EXPECT_TRUE(element->Is<UintValue>());
  EXPECT_EQ(element.As<UintValue>()->NativeValue(), 1);
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 2));
  EXPECT_TRUE(element->Is<UintValue>());
  EXPECT_EQ(element.As<UintValue>()->NativeValue(), 2);
}

TEST(ListValueBuilder, Double) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
  auto list_builder = ListValueBuilder<DoubleValue>(
      value_factory, type_factory.GetDoubleType());
  list_builder.Reserve(3);
  EXPECT_TRUE(list_builder.IsEmpty());
  auto value = value_factory.CreateDoubleValue(1.0).As<Value>();
  EXPECT_OK(list_builder.Add(0.0));
  EXPECT_OK(list_builder.Add(value));  // lvalue
  EXPECT_OK(list_builder.Add(
      value_factory.CreateDoubleValue(2.0).As<Value>()));  // rvalue
  EXPECT_EQ(list_builder.Size(), 3);
  EXPECT_EQ(list_builder.DebugString(), "[0.0, 1.0, 2.0]");
  ASSERT_OK_AND_ASSIGN(auto list, std::move(list_builder).Build());
  EXPECT_EQ(list->Size(), 3);
  EXPECT_EQ(list->DebugString(), "[0.0, 1.0, 2.0]");
  ASSERT_OK_AND_ASSIGN(auto element, list->Get(value_factory, 0));
  EXPECT_TRUE(element->Is<DoubleValue>());
  EXPECT_EQ(element.As<DoubleValue>()->NativeValue(), 0);
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 1));
  EXPECT_TRUE(element->Is<DoubleValue>());
  EXPECT_EQ(element.As<DoubleValue>()->NativeValue(), 1);
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 2));
  EXPECT_TRUE(element->Is<DoubleValue>());
  EXPECT_EQ(element.As<DoubleValue>()->NativeValue(), 2);
}

TEST(ListValueBuilder, Duration) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
  auto list_builder = ListValueBuilder<DurationValue>(
      value_factory, type_factory.GetDurationType());
  list_builder.Reserve(3);
  EXPECT_TRUE(list_builder.IsEmpty());
  auto value =
      value_factory.CreateUncheckedDurationValue(absl::Seconds(1)).As<Value>();
  EXPECT_OK(list_builder.Add(absl::ZeroDuration()));
  EXPECT_OK(list_builder.Add(value));  // lvalue
  EXPECT_OK(list_builder.Add(
      value_factory.CreateUncheckedDurationValue(absl::Minutes(1))
          .As<Value>()));  // rvalue
  EXPECT_EQ(list_builder.Size(), 3);
  EXPECT_EQ(list_builder.DebugString(), "[0, 1s, 1m]");
  ASSERT_OK_AND_ASSIGN(auto list, std::move(list_builder).Build());
  EXPECT_EQ(list->Size(), 3);
  EXPECT_EQ(list->DebugString(), "[0, 1s, 1m]");
  ASSERT_OK_AND_ASSIGN(auto element, list->Get(value_factory, 0));
  EXPECT_TRUE(element->Is<DurationValue>());
  EXPECT_EQ(element.As<DurationValue>()->NativeValue(), absl::ZeroDuration());
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 1));
  EXPECT_TRUE(element->Is<DurationValue>());
  EXPECT_EQ(element.As<DurationValue>()->NativeValue(), absl::Seconds(1));
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 2));
  EXPECT_TRUE(element->Is<DurationValue>());
  EXPECT_EQ(element.As<DurationValue>()->NativeValue(), absl::Minutes(1));
}

TEST(ListValueBuilder, Timestamp) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
  auto list_builder = ListValueBuilder<TimestampValue>(
      value_factory, type_factory.GetTimestampType());
  list_builder.Reserve(3);
  EXPECT_TRUE(list_builder.IsEmpty());
  auto value =
      value_factory
          .CreateUncheckedTimestampValue(absl::UnixEpoch() + absl::Seconds(1))
          .As<Value>();
  EXPECT_OK(list_builder.Add(absl::UnixEpoch()));
  EXPECT_OK(list_builder.Add(value));  // lvalue
  EXPECT_OK(list_builder.Add(
      value_factory
          .CreateUncheckedTimestampValue(absl::UnixEpoch() + absl::Minutes(1))
          .As<Value>()));  // rvalue
  EXPECT_EQ(list_builder.Size(), 3);
  EXPECT_EQ(
      list_builder.DebugString(),
      "[1970-01-01T00:00:00Z, 1970-01-01T00:00:01Z, 1970-01-01T00:01:00Z]");
  ASSERT_OK_AND_ASSIGN(auto list, std::move(list_builder).Build());
  EXPECT_EQ(list->Size(), 3);
  EXPECT_EQ(
      list->DebugString(),
      "[1970-01-01T00:00:00Z, 1970-01-01T00:00:01Z, 1970-01-01T00:01:00Z]");
  ASSERT_OK_AND_ASSIGN(auto element, list->Get(value_factory, 0));
  EXPECT_TRUE(element->Is<TimestampValue>());
  EXPECT_EQ(element.As<TimestampValue>()->NativeValue(),
            absl::UnixEpoch() + absl::ZeroDuration());
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 1));
  EXPECT_TRUE(element->Is<TimestampValue>());
  EXPECT_EQ(element.As<TimestampValue>()->NativeValue(),
            absl::UnixEpoch() + absl::Seconds(1));
  ASSERT_OK_AND_ASSIGN(element, list->Get(value_factory, 2));
  EXPECT_TRUE(element->Is<TimestampValue>());
  EXPECT_EQ(element.As<TimestampValue>()->NativeValue(),
            absl::UnixEpoch() + absl::Minutes(1));
}
template <typename I, typename T>
void TestListValueBuilderImpl(ValueFactory& value_factory,
                              const Handle<T>& element) {
  ASSERT_OK_AND_ASSIGN(auto type,
                       value_factory.type_factory().CreateListType(element));
  ASSERT_OK_AND_ASSIGN(auto builder, type->NewValueBuilder(value_factory));
  EXPECT_THAT((builder.get()), WhenDynamicCastTo<I*>(NotNull()));
}

TEST(ListValueBuilder, Dynamic) {
  TypeFactory type_factory(MemoryManagerRef::ReferenceCounting());
  TypeManager type_manager(type_factory, TypeProvider::Builtin());
  ValueFactory value_factory(type_manager);
#ifdef ABSL_INTERNAL_HAS_RTTI
  ASSERT_NO_FATAL_FAILURE(
      ((TestListValueBuilderImpl<ListValueBuilder<BoolValue>>(
          value_factory, type_factory.GetBoolType()))));
  ASSERT_NO_FATAL_FAILURE(
      ((TestListValueBuilderImpl<ListValueBuilder<IntValue>>(
          value_factory, type_factory.GetIntType()))));
  ASSERT_NO_FATAL_FAILURE(
      ((TestListValueBuilderImpl<ListValueBuilder<UintValue>>(
          value_factory, type_factory.GetUintType()))));
  ASSERT_NO_FATAL_FAILURE(
      ((TestListValueBuilderImpl<ListValueBuilder<DoubleValue>>(
          value_factory, type_factory.GetDoubleType()))));
  ASSERT_NO_FATAL_FAILURE(
      ((TestListValueBuilderImpl<ListValueBuilder<DurationValue>>(
          value_factory, type_factory.GetDurationType()))));
  ASSERT_NO_FATAL_FAILURE(
      ((TestListValueBuilderImpl<ListValueBuilder<TimestampValue>>(
          value_factory, type_factory.GetTimestampType()))));
  ASSERT_NO_FATAL_FAILURE(((TestListValueBuilderImpl<ListValueBuilder<Value>>(
      value_factory, type_factory.GetDynType()))));
#else
  GTEST_SKIP() << "RTTI unavailable";
#endif
}

}  // namespace
}  // namespace cel
