// Copyright 2022 Google LLC
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

#include "extensions/protobuf/ast_converters.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "google/api/expr/v1alpha1/checked.pb.h"
#include "google/api/expr/v1alpha1/syntax.pb.h"
#include "google/protobuf/duration.pb.h"
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/variant.h"
#include "base/ast_internal/ast_impl.h"
#include "base/ast_internal/expr.h"
#include "internal/proto_matchers.h"
#include "internal/testing.h"
#include "parser/options.h"
#include "parser/parser.h"
#include "google/protobuf/text_format.h"

namespace cel::extensions {
namespace internal {
namespace {

using ::cel::ast_internal::NullValue;
using ::cel::ast_internal::PrimitiveType;
using ::cel::ast_internal::WellKnownType;
using testing::ElementsAreArray;
using cel::internal::StatusIs;

TEST(AstConvertersTest, IdentToNative) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        ident_expr { name: "name" }
      )pb",
      &expr));

  auto native_expr = ConvertProtoExprToNative(expr);

  ASSERT_TRUE(native_expr->has_ident_expr());
  EXPECT_EQ(native_expr->ident_expr().name(), "name");
}

TEST(AstConvertersTest, SelectToNative) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        select_expr {
          operand { ident_expr { name: "name" } }
          field: "field"
          test_only: true
        }
      )pb",
      &expr));

  ASSERT_OK_AND_ASSIGN(auto native_expr, ConvertProtoExprToNative(expr));

  ASSERT_TRUE(native_expr.has_select_expr());
  auto& native_select = native_expr.select_expr();
  ASSERT_TRUE(native_select.operand().has_ident_expr());
  EXPECT_EQ(native_select.operand().ident_expr().name(), "name");
  EXPECT_EQ(native_select.field(), "field");
  EXPECT_TRUE(native_select.test_only());
}

TEST(AstConvertersTest, CallToNative) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        call_expr {
          target { ident_expr { name: "name" } }
          function: "function"
          args { ident_expr { name: "arg1" } }
          args { ident_expr { name: "arg2" } }
        }
      )pb",
      &expr));

  ASSERT_OK_AND_ASSIGN(auto native_expr, ConvertProtoExprToNative(expr));

  ASSERT_TRUE(native_expr.has_call_expr());
  auto& native_call = native_expr.call_expr();
  ASSERT_TRUE(native_call.target().has_ident_expr());
  EXPECT_EQ(native_call.target().ident_expr().name(), "name");
  EXPECT_EQ(native_call.function(), "function");
  auto& native_arg1 = native_call.args()[0];
  ASSERT_TRUE(native_arg1.has_ident_expr());
  EXPECT_EQ(native_arg1.ident_expr().name(), "arg1");
  auto& native_arg2 = native_call.args()[1];
  ASSERT_TRUE(native_arg2.has_ident_expr());
  ASSERT_EQ(native_arg2.ident_expr().name(), "arg2");
}

TEST(AstConvertersTest, CreateListToNative) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        list_expr {
          elements { ident_expr { name: "elem1" } }
          elements { ident_expr { name: "elem2" } }
          optional_indices: [ 0 ]
        }
      )pb",
      &expr));

  ASSERT_OK_AND_ASSIGN(auto native_expr, ConvertProtoExprToNative(expr));

  ASSERT_TRUE(native_expr.has_list_expr());
  auto& native_create_list = native_expr.list_expr();
  auto& native_elem1 = native_create_list.elements()[0];
  ASSERT_TRUE(native_elem1.has_ident_expr());
  ASSERT_EQ(native_elem1.ident_expr().name(), "elem1");
  auto& native_elem2 = native_create_list.elements()[1];
  ASSERT_TRUE(native_elem2.has_ident_expr());
  ASSERT_EQ(native_elem2.ident_expr().name(), "elem2");
  ASSERT_THAT(native_create_list.optional_indices(),
              ElementsAreArray(expr.list_expr().optional_indices()));
}

TEST(AstConvertersTest, CreateStructToNative) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        struct_expr {
          entries {
            id: 1
            field_key: "key1"
            value { ident_expr { name: "value1" } }
            optional_entry: true
          }
          entries {
            id: 2
            map_key { ident_expr { name: "key2" } }
            value { ident_expr { name: "value2" } }
          }
        }
      )pb",
      &expr));

  auto native_expr = ConvertProtoExprToNative(expr);

  ASSERT_TRUE(native_expr->has_struct_expr());
  auto& native_struct = native_expr->struct_expr();
  auto& native_entry1 = native_struct.entries()[0];
  EXPECT_EQ(native_entry1.id(), 1);
  ASSERT_TRUE(native_entry1.has_field_key());
  ASSERT_EQ(native_entry1.field_key(), "key1");
  ASSERT_TRUE(native_entry1.value().has_ident_expr());
  ASSERT_EQ(native_entry1.value().ident_expr().name(), "value1");
  ASSERT_TRUE(native_entry1.optional_entry());
  auto& native_entry2 = native_struct.entries()[1];
  EXPECT_EQ(native_entry2.id(), 2);
  ASSERT_TRUE(native_entry2.has_map_key());
  ASSERT_TRUE(native_entry2.map_key().has_ident_expr());
  EXPECT_EQ(native_entry2.map_key().ident_expr().name(), "key2");
  ASSERT_EQ(native_entry2.value().ident_expr().name(), "value2");
}

TEST(AstConvertersTest, CreateStructError) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        struct_expr {
          entries {
            id: 1
            value { ident_expr { name: "value" } }
          }
        }
      )pb",
      &expr));

  auto native_expr = ConvertProtoExprToNative(expr);

  EXPECT_EQ(native_expr.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(native_expr.status().message(),
              ::testing::HasSubstr(
                  "Illegal type provided for "
                  "google::api::expr::v1alpha1::Expr::CreateStruct::Entry::key_kind."));
}

TEST(AstConvertersTest, ComprehensionToNative) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        comprehension_expr {
          iter_var: "iter_var"
          iter_range { ident_expr { name: "iter_range" } }
          accu_var: "accu_var"
          accu_init { ident_expr { name: "accu_init" } }
          loop_condition { ident_expr { name: "loop_condition" } }
          loop_step { ident_expr { name: "loop_step" } }
          result { ident_expr { name: "result" } }
        }
      )pb",
      &expr));

  auto native_expr = ConvertProtoExprToNative(expr);

  ASSERT_TRUE(native_expr->has_comprehension_expr());
  auto& native_comprehension = native_expr->comprehension_expr();
  EXPECT_EQ(native_comprehension.iter_var(), "iter_var");
  ASSERT_TRUE(native_comprehension.iter_range().has_ident_expr());
  EXPECT_EQ(native_comprehension.iter_range().ident_expr().name(),
            "iter_range");
  EXPECT_EQ(native_comprehension.accu_var(), "accu_var");
  ASSERT_TRUE(native_comprehension.accu_init().has_ident_expr());
  EXPECT_EQ(native_comprehension.accu_init().ident_expr().name(), "accu_init");
  ASSERT_TRUE(native_comprehension.loop_condition().has_ident_expr());
  EXPECT_EQ(native_comprehension.loop_condition().ident_expr().name(),
            "loop_condition");
  ASSERT_TRUE(native_comprehension.loop_step().has_ident_expr());
  EXPECT_EQ(native_comprehension.loop_step().ident_expr().name(), "loop_step");
  ASSERT_TRUE(native_comprehension.result().has_ident_expr());
  EXPECT_EQ(native_comprehension.result().ident_expr().name(), "result");
}

TEST(AstConvertersTest, ComplexityLimit) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        id: 1
        call_expr {
          function: "_+_"
          args {
            id: 2
            const_expr { int64_value: 1 }
          }
          args {
            id: 3
            const_expr { int64_value: 1 }
          }
        }
      )pb",
      &expr));

  constexpr int kLogComplexityLimit = 20;
  for (int i = 0; i < kLogComplexityLimit - 1; i++) {
    google::api::expr::v1alpha1::Expr next;
    next.mutable_call_expr()->set_function("_+_");
    *(next.mutable_call_expr()->add_args()) = expr;
    *(next.mutable_call_expr()->add_args()) = std::move(expr);
    expr = std::move(next);
  }

  auto status_or = ConvertProtoExprToNative(expr);

  EXPECT_THAT(status_or, StatusIs(absl::StatusCode::kInternal,
                                  testing::HasSubstr("max iterations")));
}

TEST(AstConvertersTest, ConstantToNative) {
  google::api::expr::v1alpha1::Expr expr;
  auto* constant = expr.mutable_const_expr();
  constant->set_null_value(google::protobuf::NULL_VALUE);

  auto native_expr = ConvertProtoExprToNative(expr);

  ASSERT_TRUE(native_expr->has_const_expr());
  auto& native_constant = native_expr->const_expr();
  ASSERT_TRUE(native_constant.has_null_value());
  EXPECT_EQ(native_constant.null_value(), NullValue::kNullValue);
}

TEST(AstConvertersTest, ConstantBoolTrueToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.set_bool_value(true);

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_bool_value());
  EXPECT_TRUE(native_constant->bool_value());
}

TEST(AstConvertersTest, ConstantBoolFalseToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.set_bool_value(false);

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_bool_value());
  EXPECT_FALSE(native_constant->bool_value());
}

TEST(AstConvertersTest, ConstantInt64ToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.set_int64_value(-23);

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_int64_value());
  ASSERT_FALSE(native_constant->has_uint64_value());
  EXPECT_EQ(native_constant->int64_value(), -23);
}

TEST(AstConvertersTest, ConstantUint64ToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.set_uint64_value(23);

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_uint64_value());
  ASSERT_FALSE(native_constant->has_int64_value());
  EXPECT_EQ(native_constant->uint64_value(), 23);
}

TEST(AstConvertersTest, ConstantDoubleToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.set_double_value(12.34);

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_double_value());
  EXPECT_EQ(native_constant->double_value(), 12.34);
}

TEST(AstConvertersTest, ConstantStringToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.set_string_value("string");

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_string_value());
  EXPECT_EQ(native_constant->string_value(), "string");
}

TEST(AstConvertersTest, ConstantBytesToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.set_bytes_value("bytes");

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_bytes_value());
  EXPECT_EQ(native_constant->bytes_value(), "bytes");
}

TEST(AstConvertersTest, ConstantDurationToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.mutable_duration_value()->set_seconds(123);
  constant.mutable_duration_value()->set_nanos(456);

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_duration_value());
  EXPECT_EQ(native_constant->duration_value(),
            absl::Seconds(123) + absl::Nanoseconds(456));
}

TEST(AstConvertersTest, ConstantTimestampToNative) {
  google::api::expr::v1alpha1::Constant constant;
  constant.mutable_timestamp_value()->set_seconds(123);
  constant.mutable_timestamp_value()->set_nanos(456);

  auto native_constant = ConvertConstant(constant);

  ASSERT_TRUE(native_constant->has_time_value());
  EXPECT_EQ(native_constant->time_value(),
            absl::FromUnixSeconds(123) + absl::Nanoseconds(456));
}

TEST(AstConvertersTest, ConstantError) {
  auto native_constant = ConvertConstant(google::api::expr::v1alpha1::Constant());

  EXPECT_EQ(native_constant.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(native_constant.status().message(),
              ::testing::HasSubstr("Unsupported constant type"));
}

TEST(AstConvertersTest, ExprUnset) {
  auto native_expr = ConvertProtoExprToNative(google::api::expr::v1alpha1::Expr());

  EXPECT_TRUE(
      absl::holds_alternative<absl::monostate>(native_expr->expr_kind()));
}

TEST(AstConvertersTest, SourceInfoToNative) {
  google::api::expr::v1alpha1::SourceInfo source_info;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        syntax_version: "version"
        location: "location"
        line_offsets: 1
        line_offsets: 2
        positions { key: 1 value: 2 }
        positions { key: 3 value: 4 }
        macro_calls {
          key: 1
          value { ident_expr { name: "name" } }
        }
      )pb",
      &source_info));

  auto native_source_info = ConvertProtoSourceInfoToNative(source_info);

  EXPECT_EQ(native_source_info->syntax_version(), "version");
  EXPECT_EQ(native_source_info->location(), "location");
  EXPECT_EQ(native_source_info->line_offsets(), std::vector<int32_t>({1, 2}));
  EXPECT_EQ(native_source_info->positions().at(1), 2);
  EXPECT_EQ(native_source_info->positions().at(3), 4);
  ASSERT_TRUE(native_source_info->macro_calls().at(1).has_ident_expr());
  ASSERT_EQ(native_source_info->macro_calls().at(1).ident_expr().name(),
            "name");
}

TEST(AstConvertersTest, ParsedExprToNative) {
  google::api::expr::v1alpha1::ParsedExpr parsed_expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        expr { ident_expr { name: "name" } }
        source_info {
          syntax_version: "version"
          location: "location"
          line_offsets: 1
          line_offsets: 2
          positions { key: 1 value: 2 }
          positions { key: 3 value: 4 }
          macro_calls {
            key: 1
            value { ident_expr { name: "name" } }
          }
        }
      )pb",
      &parsed_expr));

  auto native_parsed_expr = ConvertProtoParsedExprToNative(parsed_expr);

  ASSERT_TRUE(native_parsed_expr->expr().has_ident_expr());
  ASSERT_EQ(native_parsed_expr->expr().ident_expr().name(), "name");
  auto& native_source_info = native_parsed_expr->source_info();
  EXPECT_EQ(native_source_info.syntax_version(), "version");
  EXPECT_EQ(native_source_info.location(), "location");
  EXPECT_EQ(native_source_info.line_offsets(), std::vector<int32_t>({1, 2}));
  EXPECT_EQ(native_source_info.positions().at(1), 2);
  EXPECT_EQ(native_source_info.positions().at(3), 4);
  ASSERT_TRUE(native_source_info.macro_calls().at(1).has_ident_expr());
  ASSERT_EQ(native_source_info.macro_calls().at(1).ident_expr().name(), "name");
}

TEST(AstConvertersTest, PrimitiveTypeUnspecifiedToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_primitive(google::api::expr::v1alpha1::Type::PRIMITIVE_TYPE_UNSPECIFIED);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_primitive());
  EXPECT_EQ(native_type->primitive(), PrimitiveType::kPrimitiveTypeUnspecified);
}

TEST(AstConvertersTest, PrimitiveTypeBoolToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_primitive(google::api::expr::v1alpha1::Type::BOOL);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_primitive());
  EXPECT_EQ(native_type->primitive(), PrimitiveType::kBool);
}

TEST(AstConvertersTest, PrimitiveTypeInt64ToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_primitive(google::api::expr::v1alpha1::Type::INT64);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_primitive());
  EXPECT_EQ(native_type->primitive(), PrimitiveType::kInt64);
}

TEST(AstConvertersTest, PrimitiveTypeUint64ToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_primitive(google::api::expr::v1alpha1::Type::UINT64);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_primitive());
  EXPECT_EQ(native_type->primitive(), PrimitiveType::kUint64);
}

TEST(AstConvertersTest, PrimitiveTypeDoubleToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_primitive(google::api::expr::v1alpha1::Type::DOUBLE);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_primitive());
  EXPECT_EQ(native_type->primitive(), PrimitiveType::kDouble);
}

TEST(AstConvertersTest, PrimitiveTypeStringToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_primitive(google::api::expr::v1alpha1::Type::STRING);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_primitive());
  EXPECT_EQ(native_type->primitive(), PrimitiveType::kString);
}

TEST(AstConvertersTest, PrimitiveTypeBytesToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_primitive(google::api::expr::v1alpha1::Type::BYTES);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_primitive());
  EXPECT_EQ(native_type->primitive(), PrimitiveType::kBytes);
}

TEST(AstConvertersTest, PrimitiveTypeError) {
  google::api::expr::v1alpha1::Type type;
  type.set_primitive(::google::api::expr::v1alpha1::Type_PrimitiveType(7));

  auto native_type = ConvertProtoTypeToNative(type);

  EXPECT_EQ(native_type.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(native_type.status().message(),
              ::testing::HasSubstr("Illegal type specified for "
                                   "google::api::expr::v1alpha1::Type::PrimitiveType."));
}

TEST(AstConvertersTest, WellKnownTypeUnspecifiedToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_well_known(google::api::expr::v1alpha1::Type::WELL_KNOWN_TYPE_UNSPECIFIED);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_well_known());
  EXPECT_EQ(native_type->well_known(),
            WellKnownType::kWellKnownTypeUnspecified);
}

TEST(AstConvertersTest, WellKnownTypeAnyToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_well_known(google::api::expr::v1alpha1::Type::ANY);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_well_known());
  EXPECT_EQ(native_type->well_known(), WellKnownType::kAny);
}

TEST(AstConvertersTest, WellKnownTypeTimestampToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_well_known(google::api::expr::v1alpha1::Type::TIMESTAMP);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_well_known());
  EXPECT_EQ(native_type->well_known(), WellKnownType::kTimestamp);
}

TEST(AstConvertersTest, WellKnownTypeDuraionToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_well_known(google::api::expr::v1alpha1::Type::DURATION);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_well_known());
  EXPECT_EQ(native_type->well_known(), WellKnownType::kDuration);
}

TEST(AstConvertersTest, WellKnownTypeError) {
  google::api::expr::v1alpha1::Type type;
  type.set_well_known(::google::api::expr::v1alpha1::Type_WellKnownType(4));

  auto native_type = ConvertProtoTypeToNative(type);

  EXPECT_EQ(native_type.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(native_type.status().message(),
              ::testing::HasSubstr("Illegal type specified for "
                                   "google::api::expr::v1alpha1::Type::WellKnownType."));
}

TEST(AstConvertersTest, ListTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  type.mutable_list_type()->mutable_elem_type()->set_primitive(
      google::api::expr::v1alpha1::Type::BOOL);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_list_type());
  auto& native_list_type = native_type->list_type();
  ASSERT_TRUE(native_list_type.elem_type().has_primitive());
  EXPECT_EQ(native_list_type.elem_type().primitive(), PrimitiveType::kBool);
}

TEST(AstConvertersTest, MapTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        map_type {
          key_type { primitive: BOOL }
          value_type { primitive: DOUBLE }
        }
      )pb",
      &type));

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_map_type());
  auto& native_map_type = native_type->map_type();
  ASSERT_TRUE(native_map_type.key_type().has_primitive());
  EXPECT_EQ(native_map_type.key_type().primitive(), PrimitiveType::kBool);
  ASSERT_TRUE(native_map_type.value_type().has_primitive());
  EXPECT_EQ(native_map_type.value_type().primitive(), PrimitiveType::kDouble);
}

TEST(AstConvertersTest, FunctionTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        function {
          result_type { primitive: BOOL }
          arg_types { primitive: DOUBLE }
          arg_types { primitive: STRING }
        }
      )pb",
      &type));

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_function());
  auto& native_function_type = native_type->function();
  ASSERT_TRUE(native_function_type.result_type().has_primitive());
  EXPECT_EQ(native_function_type.result_type().primitive(),
            PrimitiveType::kBool);
  ASSERT_TRUE(native_function_type.arg_types().at(0).has_primitive());
  EXPECT_EQ(native_function_type.arg_types().at(0).primitive(),
            PrimitiveType::kDouble);
  ASSERT_TRUE(native_function_type.arg_types().at(1).has_primitive());
  EXPECT_EQ(native_function_type.arg_types().at(1).primitive(),
            PrimitiveType::kString);
}

TEST(AstConvertersTest, AbstractTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        abstract_type {
          name: "name"
          parameter_types { primitive: DOUBLE }
          parameter_types { primitive: STRING }
        }
      )pb",
      &type));

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_abstract_type());
  auto& native_abstract_type = native_type->abstract_type();
  EXPECT_EQ(native_abstract_type.name(), "name");
  ASSERT_TRUE(native_abstract_type.parameter_types().at(0).has_primitive());
  EXPECT_EQ(native_abstract_type.parameter_types().at(0).primitive(),
            PrimitiveType::kDouble);
  ASSERT_TRUE(native_abstract_type.parameter_types().at(1).has_primitive());
  EXPECT_EQ(native_abstract_type.parameter_types().at(1).primitive(),
            PrimitiveType::kString);
}

TEST(AstConvertersTest, DynamicTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  type.mutable_dyn();

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_dyn());
}

TEST(AstConvertersTest, NullTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_null(google::protobuf::NULL_VALUE);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_null());
  EXPECT_EQ(native_type->null(), NullValue::kNullValue);
}

TEST(AstConvertersTest, PrimitiveTypeWrapperToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_wrapper(google::api::expr::v1alpha1::Type::BOOL);

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_wrapper());
  EXPECT_EQ(native_type->wrapper(), PrimitiveType::kBool);
}

TEST(AstConvertersTest, MessageTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_message_type("message");

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_message_type());
  EXPECT_EQ(native_type->message_type().type(), "message");
}

TEST(AstConvertersTest, ParamTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  type.set_type_param("param");

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_type_param());
  EXPECT_EQ(native_type->type_param().type(), "param");
}

TEST(AstConvertersTest, NestedTypeToNative) {
  google::api::expr::v1alpha1::Type type;
  type.mutable_type()->mutable_dyn();

  auto native_type = ConvertProtoTypeToNative(type);

  ASSERT_TRUE(native_type->has_type());
  EXPECT_TRUE(native_type->type().has_dyn());
}

TEST(AstConvertersTest, TypeError) {
  auto native_type = ConvertProtoTypeToNative(google::api::expr::v1alpha1::Type());

  EXPECT_EQ(native_type.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(native_type.status().message(),
              ::testing::HasSubstr(
                  "Illegal type specified for google::api::expr::v1alpha1::Type."));
}

TEST(AstConvertersTest, ReferenceToNative) {
  google::api::expr::v1alpha1::Reference reference;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        name: "name"
        overload_id: "id1"
        overload_id: "id2"
        value { bool_value: true }
      )pb",
      &reference));

  auto native_reference = ConvertProtoReferenceToNative(reference);

  EXPECT_EQ(native_reference->name(), "name");
  EXPECT_EQ(native_reference->overload_id(),
            std::vector<std::string>({"id1", "id2"}));
  EXPECT_TRUE(native_reference->value().bool_value());
}

TEST(AstConvertersTest, CheckedExprToNative) {
  google::api::expr::v1alpha1::CheckedExpr checked_expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        reference_map {
          key: 1
          value {
            name: "name"
            overload_id: "id1"
            overload_id: "id2"
            value { bool_value: true }
          }
        }
        type_map {
          key: 1
          value { dyn {} }
        }
        source_info {
          syntax_version: "version"
          location: "location"
          line_offsets: 1
          line_offsets: 2
          positions { key: 1 value: 2 }
          positions { key: 3 value: 4 }
          macro_calls {
            key: 1
            value { ident_expr { name: "name" } }
          }
        }
        expr_version: "version"
        expr { ident_expr { name: "expr" } }
      )pb",
      &checked_expr));

  auto native_checked_expr = ConvertProtoCheckedExprToNative(checked_expr);

  EXPECT_EQ(native_checked_expr->reference_map().at(1).name(), "name");
  EXPECT_EQ(native_checked_expr->reference_map().at(1).overload_id(),
            std::vector<std::string>({"id1", "id2"}));
  EXPECT_TRUE(native_checked_expr->reference_map().at(1).value().bool_value());
  auto& native_source_info = native_checked_expr->source_info();
  EXPECT_EQ(native_source_info.syntax_version(), "version");
  EXPECT_EQ(native_source_info.location(), "location");
  EXPECT_EQ(native_source_info.line_offsets(), std::vector<int32_t>({1, 2}));
  EXPECT_EQ(native_source_info.positions().at(1), 2);
  EXPECT_EQ(native_source_info.positions().at(3), 4);
  ASSERT_TRUE(native_source_info.macro_calls().at(1).has_ident_expr());
  ASSERT_EQ(native_source_info.macro_calls().at(1).ident_expr().name(), "name");
  EXPECT_EQ(native_checked_expr->expr_version(), "version");
  ASSERT_TRUE(native_checked_expr->expr().has_ident_expr());
  EXPECT_EQ(native_checked_expr->expr().ident_expr().name(), "expr");
}

}  // namespace
}  // namespace internal

namespace {

using ::cel::internal::test::EqualsProto;
using ::google::api::expr::parser::Parse;
using testing::HasSubstr;
using cel::internal::IsOkAndHolds;
using cel::internal::StatusIs;

using ParsedExprPb = google::api::expr::v1alpha1::ParsedExpr;
using CheckedExprPb = google::api::expr::v1alpha1::CheckedExpr;
using TypePb = google::api::expr::v1alpha1::Type;

TEST(AstConvertersTest, CheckedExprToAst) {
  CheckedExprPb checked_expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        reference_map {
          key: 1
          value {
            name: "name"
            overload_id: "id1"
            overload_id: "id2"
            value { bool_value: true }
          }
        }
        type_map {
          key: 1
          value { dyn {} }
        }
        source_info {
          syntax_version: "version"
          location: "location"
          line_offsets: 1
          line_offsets: 2
          positions { key: 1 value: 2 }
          positions { key: 3 value: 4 }
          macro_calls {
            key: 1
            value { ident_expr { name: "name" } }
          }
        }
        expr_version: "version"
        expr { ident_expr { name: "expr" } }
      )pb",
      &checked_expr));

  ASSERT_OK_AND_ASSIGN(auto ast, CreateAstFromCheckedExpr(checked_expr));

  ASSERT_TRUE(ast->IsChecked());
}

TEST(AstConvertersTest, AstToCheckedExprBasic) {
  ast_internal::Expr expr;
  expr.set_id(1);
  expr.mutable_ident_expr().set_name("expr");

  ast_internal::SourceInfo source_info;
  source_info.set_syntax_version("version");
  source_info.set_location("location");
  source_info.mutable_line_offsets().push_back(1);
  source_info.mutable_line_offsets().push_back(2);
  source_info.mutable_positions().insert({1, 2});
  source_info.mutable_positions().insert({3, 4});

  ast_internal::Expr macro;
  macro.mutable_ident_expr().set_name("name");
  source_info.mutable_macro_calls().insert({1, std::move(macro)});

  absl::flat_hash_map<int64_t, ast_internal::Type> type_map;
  absl::flat_hash_map<int64_t, ast_internal::Reference> reference_map;

  ast_internal::Reference reference;
  reference.set_name("name");
  reference.mutable_overload_id().push_back("id1");
  reference.mutable_overload_id().push_back("id2");
  reference.mutable_value().set_bool_value(true);

  ast_internal::Type type;
  type.set_type_kind(ast_internal::DynamicType());

  ast_internal::CheckedExpr checked_expr;

  checked_expr.mutable_reference_map().insert({1, std::move(reference)});
  checked_expr.mutable_type_map().insert({1, std::move(type)});
  checked_expr.mutable_source_info() = std::move(source_info);
  checked_expr.set_expr_version("version");
  checked_expr.mutable_expr() = std::move(expr);

  ast_internal::AstImpl ast(std::move(checked_expr));

  ASSERT_OK_AND_ASSIGN(auto checked_pb, CreateCheckedExprFromAst(ast));

  EXPECT_THAT(checked_pb, EqualsProto(R"pb(
                reference_map {
                  key: 1
                  value {
                    name: "name"
                    overload_id: "id1"
                    overload_id: "id2"
                    value { bool_value: true }
                  }
                }
                type_map {
                  key: 1
                  value { dyn {} }
                }
                source_info {
                  syntax_version: "version"
                  location: "location"
                  line_offsets: 1
                  line_offsets: 2
                  positions { key: 1 value: 2 }
                  positions { key: 3 value: 4 }
                  macro_calls {
                    key: 1
                    value { ident_expr { name: "name" } }
                  }
                }
                expr_version: "version"
                expr {
                  id: 1
                  ident_expr { name: "expr" }
                }
              )pb"));
}

constexpr absl::string_view kTypesTestCheckedExpr =
    R"pb(reference_map: {
           key: 1
           value: { name: "x" }
         }
         type_map: {
           key: 1
           value: { primitive: INT64 }
         }
         source_info: {
           location: "<input>"
           line_offsets: 2
           positions: { key: 1 value: 0 }
         }
         expr: {
           id: 1
           ident_expr: { name: "x" }
         })pb";

struct CheckedExprToAstTypesTestCase {
  absl::string_view type;
};

class CheckedExprToAstTypesTest
    : public testing::TestWithParam<CheckedExprToAstTypesTestCase> {
 public:
  void SetUp() override {
    ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTypesTestCheckedExpr,
                                                    &checked_expr_));
  }

 protected:
  CheckedExprPb checked_expr_;
};

TEST_P(CheckedExprToAstTypesTest, CheckedExprToAstTypes) {
  TypePb test_type;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(GetParam().type, &test_type));
  (*checked_expr_.mutable_type_map())[1] = test_type;

  ASSERT_OK_AND_ASSIGN(auto ast, CreateAstFromCheckedExpr(checked_expr_));

  EXPECT_THAT(CreateCheckedExprFromAst(*ast),
              IsOkAndHolds(EqualsProto(checked_expr_)));
}

INSTANTIATE_TEST_SUITE_P(
    Types, CheckedExprToAstTypesTest,
    testing::ValuesIn<CheckedExprToAstTypesTestCase>({
        {R"pb(list_type { elem_type { primitive: INT64 } })pb"},
        {R"pb(map_type {
                key_type { primitive: STRING }
                value_type { primitive: INT64 }
              })pb"},
        {R"pb(message_type: "com.example.TestType")pb"},
        {R"pb(primitive: BOOL)pb"},
        {R"pb(primitive: INT64)pb"},
        {R"pb(primitive: UINT64)pb"},
        {R"pb(primitive: DOUBLE)pb"},
        {R"pb(primitive: STRING)pb"},
        {R"pb(primitive: BYTES)pb"},
        {R"pb(wrapper: BOOL)pb"},
        {R"pb(wrapper: INT64)pb"},
        {R"pb(wrapper: UINT64)pb"},
        {R"pb(wrapper: DOUBLE)pb"},
        {R"pb(wrapper: STRING)pb"},
        {R"pb(wrapper: BYTES)pb"},
        {R"pb(well_known: TIMESTAMP)pb"},
        {R"pb(well_known: DURATION)pb"},
        {R"pb(well_known: ANY)pb"},
        {R"pb(dyn {})pb"},
        {R"pb(error {})pb"},
        {R"pb(null: NULL_VALUE)pb"},
        {R"pb(
           abstract_type {
             name: "MyType"
             parameter_types { primitive: INT64 }
           }
         )pb"},
        {R"pb(
           type { primitive: INT64 }
         )pb"},
        {R"pb(type_param: "T")pb"},
        {R"pb(
           function {
             result_type { primitive: INT64 }
             arg_types { primitive: INT64 }
           }
         )pb"},
    }));

TEST(AstConvertersTest, ParsedExprToAst) {
  ParsedExprPb parsed_expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        source_info {
          syntax_version: "version"
          location: "location"
          line_offsets: 1
          line_offsets: 2
          positions { key: 1 value: 2 }
          positions { key: 3 value: 4 }
          macro_calls {
            key: 1
            value { ident_expr { name: "name" } }
          }
        }
        expr { ident_expr { name: "expr" } }
      )pb",
      &parsed_expr));

  ASSERT_OK_AND_ASSIGN(auto ast,
                       cel::extensions::CreateAstFromParsedExpr(parsed_expr));
}

TEST(AstConvertersTest, AstToParsedExprBasic) {
  ast_internal::Expr expr;
  expr.set_id(1);
  expr.mutable_ident_expr().set_name("expr");

  ast_internal::SourceInfo source_info;
  source_info.set_syntax_version("version");
  source_info.set_location("location");
  source_info.mutable_line_offsets().push_back(1);
  source_info.mutable_line_offsets().push_back(2);
  source_info.mutable_positions().insert({1, 2});
  source_info.mutable_positions().insert({3, 4});

  ast_internal::Expr macro;
  macro.mutable_ident_expr().set_name("name");
  source_info.mutable_macro_calls().insert({1, std::move(macro)});

  ast_internal::ParsedExpr parsed_expr;

  parsed_expr.mutable_source_info() = std::move(source_info);
  parsed_expr.mutable_expr() = std::move(expr);

  ast_internal::AstImpl ast(std::move(parsed_expr));

  ASSERT_OK_AND_ASSIGN(auto checked_pb, CreateParsedExprFromAst(ast));

  EXPECT_THAT(checked_pb, EqualsProto(R"pb(
                source_info {
                  syntax_version: "version"
                  location: "location"
                  line_offsets: 1
                  line_offsets: 2
                  positions { key: 1 value: 2 }
                  positions { key: 3 value: 4 }
                  macro_calls {
                    key: 1
                    value { ident_expr { name: "name" } }
                  }
                }
                expr {
                  id: 1
                  ident_expr { name: "expr" }
                }
              )pb"));
}

TEST(AstConvertersTest, ExprToAst) {
  google::api::expr::v1alpha1::Expr expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        ident_expr { name: "expr" }
      )pb",
      &expr));

  ASSERT_OK_AND_ASSIGN(auto ast,
                       cel::extensions::CreateAstFromParsedExpr(expr));
}

TEST(AstConvertersTest, ExprAndSourceInfoToAst) {
  google::api::expr::v1alpha1::Expr expr;
  google::api::expr::v1alpha1::SourceInfo source_info;

  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        syntax_version: "version"
        location: "location"
        line_offsets: 1
        line_offsets: 2
        positions { key: 1 value: 2 }
        positions { key: 3 value: 4 }
        macro_calls {
          key: 1
          value { ident_expr { name: "name" } }
        }
      )pb",
      &source_info));
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        ident_expr { name: "expr" }
      )pb",
      &expr));

  ASSERT_OK_AND_ASSIGN(
      auto ast, cel::extensions::CreateAstFromParsedExpr(expr, &source_info));
}

TEST(AstConvertersTest, EmptyNodeRoundTrip) {
  ParsedExprPb parsed_expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        expr {
          id: 1
          select_expr {
            operand {
              id: 2
              # no kind set.
            }
            field: "field"
          }
        }
        source_info {}
      )pb",
      &parsed_expr));

  ASSERT_OK_AND_ASSIGN(auto ast, CreateAstFromParsedExpr(parsed_expr));
  ASSERT_OK_AND_ASSIGN(ParsedExprPb copy, CreateParsedExprFromAst(*ast));
  EXPECT_THAT(copy, EqualsProto(parsed_expr));
}

TEST(AstConvertersTest, DurationConstantRoundTrip) {
  ParsedExprPb parsed_expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        expr {
          id: 1
          const_expr {
            # deprecated, but support existing ASTs.
            duration_value { seconds: 10 }
          }
        }
        source_info {}
      )pb",
      &parsed_expr));

  ASSERT_OK_AND_ASSIGN(auto ast, CreateAstFromParsedExpr(parsed_expr));
  ASSERT_OK_AND_ASSIGN(ParsedExprPb copy, CreateParsedExprFromAst(*ast));
  EXPECT_THAT(copy, EqualsProto(parsed_expr));
}

TEST(AstConvertersTest, TimestampConstantRoundTrip) {
  ParsedExprPb parsed_expr;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"pb(
        expr {
          id: 1
          const_expr {
            # deprecated, but support existing ASTs.
            timestamp_value { seconds: 10 }
          }
        }
        source_info {}
      )pb",
      &parsed_expr));

  ASSERT_OK_AND_ASSIGN(auto ast, CreateAstFromParsedExpr(parsed_expr));
  ASSERT_OK_AND_ASSIGN(ParsedExprPb copy, CreateParsedExprFromAst(*ast));
  EXPECT_THAT(copy, EqualsProto(parsed_expr));
}

struct ConversionRoundTripCase {
  absl::string_view expr;
};

class ConversionRoundTripTest
    : public testing::TestWithParam<ConversionRoundTripCase> {
 public:
  ConversionRoundTripTest() {
    options_.add_macro_calls = true;
    options_.enable_optional_syntax = true;
  }

 protected:
  ParserOptions options_;
};

TEST_P(ConversionRoundTripTest, ParsedExprCopyable) {
  ASSERT_OK_AND_ASSIGN(ParsedExprPb parsed_expr,
                       Parse(GetParam().expr, "<input>", options_));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Ast> ast,
                       CreateAstFromParsedExpr(parsed_expr));

  const auto& impl = ast_internal::AstImpl::CastFromPublicAst(*ast);
  ast_internal::AstImpl copy_of_impl = impl.DeepCopy();

  EXPECT_EQ(copy_of_impl.root_expr(), impl.root_expr());

  EXPECT_THAT(CreateCheckedExprFromAst(copy_of_impl),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("AST is not type-checked")));
  EXPECT_THAT(CreateParsedExprFromAst(copy_of_impl),
              IsOkAndHolds(EqualsProto(parsed_expr)));
}

TEST_P(ConversionRoundTripTest, CheckedExprCopyable) {
  ASSERT_OK_AND_ASSIGN(ParsedExprPb parsed_expr,
                       Parse(GetParam().expr, "<input>", options_));

  CheckedExprPb checked_expr;
  *checked_expr.mutable_expr() = parsed_expr.expr();
  *checked_expr.mutable_source_info() = parsed_expr.source_info();

  int64_t root_id = checked_expr.expr().id();
  (*checked_expr.mutable_reference_map())[root_id].add_overload_id("_==_");
  (*checked_expr.mutable_type_map())[root_id].set_primitive(TypePb::BOOL);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Ast> ast,
                       CreateAstFromCheckedExpr(checked_expr));

  const auto& impl = ast_internal::AstImpl::CastFromPublicAst(*ast);
  ast_internal::AstImpl copy_of_impl = impl.DeepCopy();

  EXPECT_EQ(copy_of_impl.root_expr(), impl.root_expr());
  EXPECT_EQ(copy_of_impl.type_map(), impl.type_map());
  EXPECT_EQ(copy_of_impl.reference_map(), impl.reference_map());
  EXPECT_EQ(copy_of_impl.source_info(), impl.source_info());

  EXPECT_THAT(CreateCheckedExprFromAst(copy_of_impl),
              IsOkAndHolds(EqualsProto(checked_expr)));
}

INSTANTIATE_TEST_SUITE_P(
    ExpressionCases, ConversionRoundTripTest,
    testing::ValuesIn<ConversionRoundTripCase>(
        {{R"cel(null == null)cel"},
         {R"cel(1 == 2)cel"},
         {R"cel(1u == 2u)cel"},
         {R"cel(1.1 == 2.1)cel"},
         {R"cel(b"1" == b"2")cel"},
         {R"cel("42" == "42")cel"},
         {R"cel("s".startsWith("s") == true)cel"},
         {R"cel([1, 2, 3] == [1, 2, 3])cel"},
         {R"cel(TestAllTypes{single_int64: 42}.single_int64 == 42)cel"},
         {R"cel([1, 2, 3].map(x, x + 2).size() == 3)cel"},
         {R"cel({"a": 1, "b": 2}["a"] == 1)cel"},
         {R"cel(ident == 42)cel"},
         {R"cel(ident.field == 42)cel"},
         {R"cel({?"abc": {}[?1]}.?abc.orValue(42) == 42)cel"},
         {R"cel([1, 2, ?optional.none()].size() == 2)cel"}}));

}  // namespace
}  // namespace cel::extensions
