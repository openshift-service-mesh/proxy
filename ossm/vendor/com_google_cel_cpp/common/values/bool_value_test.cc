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

#include "absl/hash/hash.h"
#include "absl/strings/cord.h"
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

TEST(BoolValue, Kind) {
  EXPECT_EQ(BoolValue(true).kind(), BoolValue::kKind);
  EXPECT_EQ(Value(BoolValue(true)).kind(), BoolValue::kKind);
}

TEST(BoolValue, Type) {
  EXPECT_EQ(BoolValue(true).type(), BoolType());
  EXPECT_EQ(Value(BoolValue(true)).type(), BoolType());
}

TEST(BoolValue, DebugString) {
  {
    std::ostringstream out;
    out << BoolValue(true);
    EXPECT_EQ(out.str(), "true");
  }
  {
    std::ostringstream out;
    out << Value(BoolValue(true));
    EXPECT_EQ(out.str(), "true");
  }
}

TEST(BoolValue, GetSerializedSize) {
  EXPECT_THAT(BoolValue(false).GetSerializedSize(), IsOkAndHolds(0));
  EXPECT_THAT(BoolValue(true).GetSerializedSize(), IsOkAndHolds(2));
}

TEST(BoolValue, ConvertToAny) {
  EXPECT_THAT(BoolValue(false).ConvertToAny(),
              IsOkAndHolds(MakeAny(MakeTypeUrl("google.protobuf.BoolValue"),
                                   absl::Cord())));
}

TEST(BoolValue, ConvertToJson) {
  EXPECT_THAT(BoolValue(false).ConvertToJson(), IsOkAndHolds(Json(false)));
}

TEST(BoolValue, NativeTypeId) {
  EXPECT_EQ(NativeTypeId::Of(BoolValue(true)), NativeTypeId::For<BoolValue>());
  EXPECT_EQ(NativeTypeId::Of(Value(BoolValue(true))),
            NativeTypeId::For<BoolValue>());
}

TEST(BoolValue, InstanceOf) {
  EXPECT_TRUE(InstanceOf<BoolValue>(BoolValue(true)));
  EXPECT_TRUE(InstanceOf<BoolValue>(Value(BoolValue(true))));
}

TEST(BoolValue, Cast) {
  EXPECT_THAT(Cast<BoolValue>(BoolValue(true)), An<BoolValue>());
  EXPECT_THAT(Cast<BoolValue>(Value(BoolValue(true))), An<BoolValue>());
}

TEST(BoolValue, As) {
  EXPECT_THAT(As<BoolValue>(BoolValue(true)), Ne(absl::nullopt));
  EXPECT_THAT(As<BoolValue>(Value(BoolValue(true))), Ne(absl::nullopt));
}

TEST(BoolValue, HashValue) {
  EXPECT_EQ(absl::HashOf(BoolValue(true)), absl::HashOf(true));
}

TEST(BoolValue, Equality) {
  EXPECT_NE(BoolValue(false), true);
  EXPECT_NE(true, BoolValue(false));
  EXPECT_NE(BoolValue(false), BoolValue(true));
}

TEST(BoolValue, LessThan) {
  EXPECT_LT(BoolValue(false), true);
  EXPECT_LT(false, BoolValue(true));
  EXPECT_LT(BoolValue(false), BoolValue(true));
}

TEST(BoolValueView, Kind) {
  EXPECT_EQ(BoolValueView(true).kind(), BoolValueView::kKind);
  EXPECT_EQ(ValueView(BoolValueView(true)).kind(), BoolValueView::kKind);
}

TEST(BoolValueView, Type) {
  EXPECT_EQ(BoolValueView(true).type(), BoolType());
  EXPECT_EQ(ValueView(BoolValueView(true)).type(), BoolType());
}

TEST(BoolValueView, DebugString) {
  {
    std::ostringstream out;
    out << BoolValueView(true);
    EXPECT_EQ(out.str(), "true");
  }
  {
    std::ostringstream out;
    out << ValueView(BoolValueView(true));
    EXPECT_EQ(out.str(), "true");
  }
}

TEST(BoolValueView, GetSerializedSize) {
  EXPECT_THAT(BoolValueView(false).GetSerializedSize(), IsOkAndHolds(0));
  EXPECT_THAT(BoolValueView(true).GetSerializedSize(), IsOkAndHolds(2));
}

TEST(BoolValueView, ConvertToAny) {
  EXPECT_THAT(BoolValueView(false).ConvertToAny(),
              IsOkAndHolds(MakeAny(MakeTypeUrl("google.protobuf.BoolValue"),
                                   absl::Cord())));
}

TEST(BoolValueView, ConvertToJson) {
  EXPECT_THAT(BoolValueView(false).ConvertToJson(), IsOkAndHolds(Json(false)));
}

TEST(BoolValueView, NativeTypeId) {
  EXPECT_EQ(NativeTypeId::Of(BoolValueView(true)),
            NativeTypeId::For<BoolValueView>());
  EXPECT_EQ(NativeTypeId::Of(ValueView(BoolValueView(true))),
            NativeTypeId::For<BoolValueView>());
}

TEST(BoolValueView, InstanceOf) {
  EXPECT_TRUE(InstanceOf<BoolValueView>(BoolValueView(true)));
  EXPECT_TRUE(InstanceOf<BoolValueView>(ValueView(BoolValueView(true))));
}

TEST(BoolValueView, Cast) {
  EXPECT_THAT(Cast<BoolValueView>(BoolValueView(true)), An<BoolValueView>());
  EXPECT_THAT(Cast<BoolValueView>(ValueView(BoolValueView(true))),
              An<BoolValueView>());
}

TEST(BoolValueView, As) {
  EXPECT_THAT(As<BoolValueView>(BoolValueView(true)), Ne(absl::nullopt));
  EXPECT_THAT(As<BoolValueView>(ValueView(BoolValueView(true))),
              Ne(absl::nullopt));
}

TEST(BoolValueView, HashValue) {
  EXPECT_EQ(absl::HashOf(BoolValueView(true)), absl::HashOf(true));
}

TEST(BoolValueView, Equality) {
  EXPECT_NE(BoolValueView(BoolValue(false)), true);
  EXPECT_NE(true, BoolValueView(false));
  EXPECT_NE(BoolValueView(false), BoolValueView(true));
  EXPECT_NE(BoolValueView(false), BoolValue(true));
  EXPECT_NE(BoolValue(true), BoolValueView(false));
}

TEST(BoolValueView, LessThan) {
  EXPECT_LT(BoolValueView(false), true);
  EXPECT_LT(false, BoolValueView(true));
  EXPECT_LT(BoolValueView(false), BoolValueView(true));
  EXPECT_LT(BoolValueView(false), BoolValue(true));
  EXPECT_LT(BoolValue(false), BoolValueView(true));
}

}  // namespace
}  // namespace cel
