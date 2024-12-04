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

#include <sstream>

#include "absl/strings/cord.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "common/any.h"
#include "common/casting.h"
#include "common/json.h"
#include "common/native_type.h"
#include "common/type.h"
#include "common/value.h"
#include "internal/testing.h"

namespace cel {
namespace {

using testing::An;
using testing::Ne;
using cel::internal::IsOkAndHolds;

TEST(TimestampValue, Kind) {
  EXPECT_EQ(TimestampValue().kind(), TimestampValue::kKind);
  EXPECT_EQ(Value(TimestampValue(absl::UnixEpoch() + absl::Seconds(1))).kind(),
            TimestampValue::kKind);
}

TEST(TimestampValue, Type) {
  EXPECT_EQ(TimestampValue(absl::UnixEpoch() + absl::Seconds(1)).type(),
            TimestampType());
  EXPECT_EQ(Value(TimestampValue(absl::UnixEpoch() + absl::Seconds(1))).type(),
            TimestampType());
}

TEST(TimestampValue, DebugString) {
  {
    std::ostringstream out;
    out << TimestampValue(absl::UnixEpoch() + absl::Seconds(1));
    EXPECT_EQ(out.str(), "1970-01-01T00:00:01Z");
  }
  {
    std::ostringstream out;
    out << Value(TimestampValue(absl::UnixEpoch() + absl::Seconds(1)));
    EXPECT_EQ(out.str(), "1970-01-01T00:00:01Z");
  }
}

TEST(TimestampValue, GetSerializedSize) {
  EXPECT_THAT(TimestampValue().GetSerializedSize(), IsOkAndHolds(0));
}

TEST(TimestampValue, ConvertToAny) {
  EXPECT_THAT(TimestampValue().ConvertToAny(),
              IsOkAndHolds(MakeAny(MakeTypeUrl("google.protobuf.Timestamp"),
                                   absl::Cord())));
}

TEST(TimestampValue, ConvertToJson) {
  EXPECT_THAT(TimestampValue().ConvertToJson(),
              IsOkAndHolds(Json(JsonString("1970-01-01T00:00:00Z"))));
}

TEST(TimestampValue, NativeTypeId) {
  EXPECT_EQ(
      NativeTypeId::Of(TimestampValue(absl::UnixEpoch() + absl::Seconds(1))),
      NativeTypeId::For<TimestampValue>());
  EXPECT_EQ(NativeTypeId::Of(
                Value(TimestampValue(absl::UnixEpoch() + absl::Seconds(1)))),
            NativeTypeId::For<TimestampValue>());
}

TEST(TimestampValue, InstanceOf) {
  EXPECT_TRUE(InstanceOf<TimestampValue>(
      TimestampValue(absl::UnixEpoch() + absl::Seconds(1))));
  EXPECT_TRUE(InstanceOf<TimestampValue>(
      Value(TimestampValue(absl::UnixEpoch() + absl::Seconds(1)))));
}

TEST(TimestampValue, Cast) {
  EXPECT_THAT(Cast<TimestampValue>(
                  TimestampValue(absl::UnixEpoch() + absl::Seconds(1))),
              An<TimestampValue>());
  EXPECT_THAT(Cast<TimestampValue>(
                  Value(TimestampValue(absl::UnixEpoch() + absl::Seconds(1)))),
              An<TimestampValue>());
}

TEST(TimestampValue, As) {
  EXPECT_THAT(
      As<TimestampValue>(TimestampValue(absl::UnixEpoch() + absl::Seconds(1))),
      Ne(absl::nullopt));
  EXPECT_THAT(As<TimestampValue>(
                  Value(TimestampValue(absl::UnixEpoch() + absl::Seconds(1)))),
              Ne(absl::nullopt));
}

TEST(TimestampValue, Equality) {
  EXPECT_NE(TimestampValue(absl::UnixEpoch()),
            absl::UnixEpoch() + absl::Seconds(1));
  EXPECT_NE(absl::UnixEpoch() + absl::Seconds(1),
            TimestampValue(absl::UnixEpoch()));
  EXPECT_NE(TimestampValue(absl::UnixEpoch()),
            TimestampValue(absl::UnixEpoch() + absl::Seconds(1)));
}

TEST(TimestampValueView, Kind) {
  EXPECT_EQ(TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)).kind(),
            TimestampValueView::kKind);
  EXPECT_EQ(ValueView(TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)))
                .kind(),
            TimestampValueView::kKind);
}

TEST(TimestampValueView, Type) {
  EXPECT_EQ(TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)).type(),
            TimestampType());
  EXPECT_EQ(ValueView(TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)))
                .type(),
            TimestampType());
}

TEST(TimestampValueView, DebugString) {
  {
    std::ostringstream out;
    out << TimestampValueView(absl::UnixEpoch() + absl::Seconds(1));
    EXPECT_EQ(out.str(), "1970-01-01T00:00:01Z");
  }
  {
    std::ostringstream out;
    out << ValueView(TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)));
    EXPECT_EQ(out.str(), "1970-01-01T00:00:01Z");
  }
}

TEST(TimestampValueView, GetSerializedSize) {
  EXPECT_THAT(TimestampValueView().GetSerializedSize(), IsOkAndHolds(0));
}

TEST(TimestampValueView, ConvertToAny) {
  EXPECT_THAT(TimestampValueView().ConvertToAny(),
              IsOkAndHolds(MakeAny(MakeTypeUrl("google.protobuf.Timestamp"),
                                   absl::Cord())));
}

TEST(TimestampValueView, ConvertToJson) {
  EXPECT_THAT(TimestampValueView().ConvertToJson(),
              IsOkAndHolds(Json(JsonString("1970-01-01T00:00:00Z"))));
}

TEST(TimestampValueView, NativeTypeId) {
  EXPECT_EQ(NativeTypeId::Of(
                TimestampValueView(absl::UnixEpoch() + absl::Seconds(1))),
            NativeTypeId::For<TimestampValueView>());
  EXPECT_EQ(NativeTypeId::Of(ValueView(
                TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)))),
            NativeTypeId::For<TimestampValueView>());
}

TEST(TimestampValueView, InstanceOf) {
  EXPECT_TRUE(InstanceOf<TimestampValueView>(
      TimestampValueView(absl::UnixEpoch() + absl::Seconds(1))));
  EXPECT_TRUE(InstanceOf<TimestampValueView>(
      ValueView(TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)))));
}

TEST(TimestampValueView, Cast) {
  EXPECT_THAT(Cast<TimestampValueView>(
                  TimestampValueView(absl::UnixEpoch() + absl::Seconds(1))),
              An<TimestampValueView>());
  EXPECT_THAT(Cast<TimestampValueView>(ValueView(
                  TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)))),
              An<TimestampValueView>());
}

TEST(TimestampValueView, As) {
  EXPECT_THAT(As<TimestampValueView>(
                  TimestampValueView(absl::UnixEpoch() + absl::Seconds(1))),
              Ne(absl::nullopt));
  EXPECT_THAT(As<TimestampValueView>(ValueView(
                  TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)))),
              Ne(absl::nullopt));
}

TEST(DurationValueView, Equality) {
  EXPECT_NE(TimestampValueView(TimestampValue(absl::UnixEpoch())),
            absl::UnixEpoch() + absl::Seconds(1));
  EXPECT_NE(absl::UnixEpoch() + absl::Seconds(1),
            TimestampValueView(absl::UnixEpoch()));
  EXPECT_NE(TimestampValueView(absl::UnixEpoch()),
            TimestampValueView(absl::UnixEpoch() + absl::Seconds(1)));
  EXPECT_NE(TimestampValueView(absl::UnixEpoch()),
            TimestampValue(absl::UnixEpoch() + absl::Seconds(1)));
  EXPECT_NE(TimestampValue(absl::UnixEpoch() + absl::Seconds(1)),
            TimestampValueView(absl::UnixEpoch()));
}

}  // namespace
}  // namespace cel
