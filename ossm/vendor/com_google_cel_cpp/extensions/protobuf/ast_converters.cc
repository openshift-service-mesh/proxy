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
#include <stack>
#include <string>
#include <utility>
#include <vector>

#include "google/api/expr/v1alpha1/checked.pb.h"
#include "google/api/expr/v1alpha1/syntax.pb.h"
#include "google/protobuf/duration.pb.h"
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include "absl/base/nullability.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "absl/types/variant.h"
#include "base/ast.h"
#include "base/ast_internal/ast_impl.h"
#include "base/ast_internal/expr.h"
#include "internal/overloaded.h"
#include "internal/proto_time_encoding.h"
#include "internal/status_macros.h"

constexpr int kMaxIterations = 1'000'000;

namespace cel::extensions {
namespace internal {
namespace {

using ::cel::ast_internal::AbstractType;
using ::cel::ast_internal::Bytes;
using ::cel::ast_internal::Call;
using ::cel::ast_internal::CheckedExpr;
using ::cel::ast_internal::Comprehension;
using ::cel::ast_internal::Constant;
using ::cel::ast_internal::CreateList;
using ::cel::ast_internal::CreateStruct;
using ::cel::ast_internal::DynamicType;
using ::cel::ast_internal::ErrorType;
using ::cel::ast_internal::Expr;
using ::cel::ast_internal::FunctionType;
using ::cel::ast_internal::Ident;
using ::cel::ast_internal::ListType;
using ::cel::ast_internal::MapType;
using ::cel::ast_internal::MessageType;
using ::cel::ast_internal::NullValue;
using ::cel::ast_internal::ParamType;
using ::cel::ast_internal::ParsedExpr;
using ::cel::ast_internal::PrimitiveType;
using ::cel::ast_internal::PrimitiveTypeWrapper;
using ::cel::ast_internal::Reference;
using ::cel::ast_internal::Select;
using ::cel::ast_internal::SourceInfo;
using ::cel::ast_internal::Type;
using ::cel::ast_internal::WellKnownType;

using ExprPb = google::api::expr::v1alpha1::Expr;
using ParsedExprPb = google::api::expr::v1alpha1::ParsedExpr;
using CheckedExprPb = google::api::expr::v1alpha1::CheckedExpr;

struct ConversionStackEntry {
  absl::Nonnull<Expr*> expr;

  absl::Nonnull<const ExprPb*> proto_expr;
};

Ident ConvertIdent(const ExprPb::Ident& ident) { return Ident(ident.name()); }

absl::StatusOr<Select> ConvertSelect(const ExprPb::Select& select,
                                     std::stack<ConversionStackEntry>& stack) {
  Select value(std::make_unique<Expr>(), select.field(), select.test_only());
  stack.push({&value.mutable_operand(), &select.operand()});
  return value;
}

absl::StatusOr<Call> ConvertCall(const ExprPb::Call& call,
                                 std::stack<ConversionStackEntry>& stack) {
  Call ret_val;
  ret_val.set_function(call.function());
  ret_val.set_args(std::vector<Expr>(call.args_size()));
  for (int i = 0; i < ret_val.args().size(); i++) {
    stack.push({&ret_val.mutable_args()[i], &call.args(i)});
  }
  if (call.has_target()) {
    stack.push({&ret_val.mutable_target(), &call.target()});
  }
  return ret_val;
}

absl::StatusOr<CreateList> ConvertCreateList(
    const ExprPb::CreateList& create_list,
    std::stack<ConversionStackEntry>& stack) {
  CreateList ret_val;
  ret_val.set_elements(std::vector<Expr>(create_list.elements_size()));
  ret_val.set_optional_indices(
      std::vector<int32_t>(create_list.optional_indices().begin(),
                           create_list.optional_indices().end()));

  for (int i = 0; i < ret_val.elements().size(); i++) {
    stack.push({&ret_val.mutable_elements()[i], &create_list.elements(i)});
  }
  return ret_val;
}

absl::StatusOr<CreateStruct::Entry::KeyKind> ConvertCreateStructEntryKey(
    const ExprPb::CreateStruct::Entry& entry,
    std::stack<ConversionStackEntry>& stack) {
  switch (entry.key_kind_case()) {
    case google::api::expr::v1alpha1::Expr_CreateStruct_Entry::kFieldKey:
      return entry.field_key();
    case google::api::expr::v1alpha1::Expr_CreateStruct_Entry::kMapKey: {
      auto native_map_key = std::make_unique<Expr>();
      stack.push({native_map_key.get(), &entry.map_key()});
      return native_map_key;
    }
    default:
      return absl::InvalidArgumentError(
          "Illegal type provided for "
          "google::api::expr::v1alpha1::Expr::CreateStruct::Entry::key_kind.");
  }
}

absl::StatusOr<CreateStruct::Entry> ConvertCreateStructEntry(
    const ExprPb::CreateStruct::Entry& entry,
    std::stack<ConversionStackEntry>& stack) {
  CEL_ASSIGN_OR_RETURN(auto native_key,
                       ConvertCreateStructEntryKey(entry, stack));

  if (!entry.has_value()) {
    return absl::InvalidArgumentError(
        "google::api::expr::v1alpha1::Expr::CreateStruct::Entry missing value");
  }
  CreateStruct::Entry result(entry.id(), std::move(native_key),
                             std::make_unique<Expr>(), entry.optional_entry());
  stack.push({&result.mutable_value(), &entry.value()});

  return result;
}

absl::StatusOr<CreateStruct> ConvertCreateStruct(
    const ExprPb::CreateStruct& create_struct,
    std::stack<ConversionStackEntry>& stack) {
  std::vector<CreateStruct::Entry> entries;
  entries.reserve(create_struct.entries_size());
  for (const auto& entry : create_struct.entries()) {
    CEL_ASSIGN_OR_RETURN(auto native_entry,
                         ConvertCreateStructEntry(entry, stack));
    entries.push_back(std::move(native_entry));
  }
  return CreateStruct(create_struct.message_name(), std::move(entries));
}

absl::StatusOr<Comprehension> ConvertComprehension(
    const google::api::expr::v1alpha1::Expr::Comprehension& comprehension,
    std::stack<ConversionStackEntry>& stack) {
  Comprehension ret_val;
  // accu_var
  if (comprehension.accu_var().empty()) {
    return absl::InvalidArgumentError(
        "Invalid comprehension: 'accu_var' must not be empty");
  }
  ret_val.set_accu_var(comprehension.accu_var());
  // iter_var
  if (comprehension.iter_var().empty()) {
    return absl::InvalidArgumentError(
        "Invalid comprehension: 'iter_var' must not be empty");
  }
  ret_val.set_iter_var(comprehension.iter_var());

  // accu_init
  if (!comprehension.has_accu_init()) {
    return absl::InvalidArgumentError(
        "Invalid comprehension: 'accu_init' must be set");
  }
  stack.push({&ret_val.mutable_accu_init(), &comprehension.accu_init()});

  // iter_range optional
  if (comprehension.has_iter_range()) {
    stack.push({&ret_val.mutable_iter_range(), &comprehension.iter_range()});
  }

  // loop_condition
  if (!comprehension.has_loop_condition()) {
    return absl::InvalidArgumentError(
        "Invalid comprehension: 'loop_condition' must be set");
  }
  stack.push(
      {&ret_val.mutable_loop_condition(), &comprehension.loop_condition()});

  // loop_step
  if (!comprehension.has_loop_step()) {
    return absl::InvalidArgumentError(
        "Invalid comprehension: 'loop_step' must be set");
  }
  stack.push({&ret_val.mutable_loop_step(), &comprehension.loop_step()});

  // result
  if (!comprehension.has_result()) {
    return absl::InvalidArgumentError(
        "Invalid comprehension: 'result' must be set");
  }
  stack.push({&ret_val.mutable_result(), &comprehension.result()});

  return ret_val;
}

absl::StatusOr<Expr> ConvertExpr(const ExprPb& expr,
                                 std::stack<ConversionStackEntry>& stack) {
  switch (expr.expr_kind_case()) {
    case google::api::expr::v1alpha1::Expr::kConstExpr: {
      CEL_ASSIGN_OR_RETURN(auto native_const,
                           ConvertConstant(expr.const_expr()));
      return Expr(expr.id(), std::move(native_const));
    }
    case google::api::expr::v1alpha1::Expr::kIdentExpr:
      return Expr(expr.id(), ConvertIdent(expr.ident_expr()));
    case google::api::expr::v1alpha1::Expr::kSelectExpr: {
      CEL_ASSIGN_OR_RETURN(auto native_select,
                           ConvertSelect(expr.select_expr(), stack));
      return Expr(expr.id(), std::move(native_select));
    }
    case google::api::expr::v1alpha1::Expr::kCallExpr: {
      CEL_ASSIGN_OR_RETURN(auto native_call,
                           ConvertCall(expr.call_expr(), stack));

      return Expr(expr.id(), std::move(native_call));
    }
    case google::api::expr::v1alpha1::Expr::kListExpr: {
      CEL_ASSIGN_OR_RETURN(auto native_list,
                           ConvertCreateList(expr.list_expr(), stack));

      return Expr(expr.id(), std::move(native_list));
    }
    case google::api::expr::v1alpha1::Expr::kStructExpr: {
      CEL_ASSIGN_OR_RETURN(auto native_struct,
                           ConvertCreateStruct(expr.struct_expr(), stack));
      return Expr(expr.id(), std::move(native_struct));
    }
    case google::api::expr::v1alpha1::Expr::kComprehensionExpr: {
      CEL_ASSIGN_OR_RETURN(
          auto native_comprehension,
          ConvertComprehension(expr.comprehension_expr(), stack));
      return Expr(expr.id(), std::move(native_comprehension));
    }
    default:
      // kind unset
      return Expr(expr.id(), absl::monostate());
  }
}

absl::StatusOr<Expr> ToNativeExprImpl(const ExprPb& proto_expr) {
  std::stack<ConversionStackEntry> conversion_stack;
  int iterations = 0;
  Expr root;
  conversion_stack.push({&root, &proto_expr});
  while (!conversion_stack.empty()) {
    ConversionStackEntry entry = conversion_stack.top();
    conversion_stack.pop();
    CEL_ASSIGN_OR_RETURN(*entry.expr,
                         ConvertExpr(*entry.proto_expr, conversion_stack));
    ++iterations;
    if (iterations > kMaxIterations) {
      return absl::InternalError(
          "max iterations exceeded in proto to native ast conversion.");
    }
  }
  return root;
}

}  // namespace

absl::StatusOr<Constant> ConvertConstant(
    const google::api::expr::v1alpha1::Constant& constant) {
  switch (constant.constant_kind_case()) {
    case google::api::expr::v1alpha1::Constant::kNullValue:
      return Constant(NullValue::kNullValue);
    case google::api::expr::v1alpha1::Constant::kBoolValue:
      return Constant(constant.bool_value());
    case google::api::expr::v1alpha1::Constant::kInt64Value:
      return Constant(constant.int64_value());
    case google::api::expr::v1alpha1::Constant::kUint64Value:
      return Constant(constant.uint64_value());
    case google::api::expr::v1alpha1::Constant::kDoubleValue:
      return Constant(constant.double_value());
    case google::api::expr::v1alpha1::Constant::kStringValue:
      return Constant(constant.string_value());
    case google::api::expr::v1alpha1::Constant::kBytesValue:
      return Constant(Bytes{constant.bytes_value()});
    case google::api::expr::v1alpha1::Constant::kDurationValue:
      return Constant(absl::Seconds(constant.duration_value().seconds()) +
                      absl::Nanoseconds(constant.duration_value().nanos()));
    case google::api::expr::v1alpha1::Constant::kTimestampValue:
      return Constant(
          absl::FromUnixSeconds(constant.timestamp_value().seconds()) +
          absl::Nanoseconds(constant.timestamp_value().nanos()));
    default:
      return absl::InvalidArgumentError("Unsupported constant type");
  }
}

absl::StatusOr<Expr> ConvertProtoExprToNative(
    const google::api::expr::v1alpha1::Expr& expr) {
  return ToNativeExprImpl(expr);
}

absl::StatusOr<SourceInfo> ConvertProtoSourceInfoToNative(
    const google::api::expr::v1alpha1::SourceInfo& source_info) {
  absl::flat_hash_map<int64_t, Expr> macro_calls;
  for (const auto& pair : source_info.macro_calls()) {
    auto native_expr = ConvertProtoExprToNative(pair.second);
    if (!native_expr.ok()) {
      return native_expr.status();
    }
    macro_calls.emplace(pair.first, *(std::move(native_expr)));
  }
  return SourceInfo(
      source_info.syntax_version(), source_info.location(),
      std::vector<int32_t>(source_info.line_offsets().begin(),
                           source_info.line_offsets().end()),
      absl::flat_hash_map<int64_t, int32_t>(source_info.positions().begin(),
                                            source_info.positions().end()),
      std::move(macro_calls));
}

absl::StatusOr<ParsedExpr> ConvertProtoParsedExprToNative(
    const google::api::expr::v1alpha1::ParsedExpr& parsed_expr) {
  auto native_expr = ConvertProtoExprToNative(parsed_expr.expr());
  if (!native_expr.ok()) {
    return native_expr.status();
  }
  auto native_source_info =
      ConvertProtoSourceInfoToNative(parsed_expr.source_info());
  if (!native_source_info.ok()) {
    return native_source_info.status();
  }
  return ParsedExpr(*(std::move(native_expr)),
                    *(std::move(native_source_info)));
}

absl::StatusOr<PrimitiveType> ToNative(
    google::api::expr::v1alpha1::Type::PrimitiveType primitive_type) {
  switch (primitive_type) {
    case google::api::expr::v1alpha1::Type::PRIMITIVE_TYPE_UNSPECIFIED:
      return PrimitiveType::kPrimitiveTypeUnspecified;
    case google::api::expr::v1alpha1::Type::BOOL:
      return PrimitiveType::kBool;
    case google::api::expr::v1alpha1::Type::INT64:
      return PrimitiveType::kInt64;
    case google::api::expr::v1alpha1::Type::UINT64:
      return PrimitiveType::kUint64;
    case google::api::expr::v1alpha1::Type::DOUBLE:
      return PrimitiveType::kDouble;
    case google::api::expr::v1alpha1::Type::STRING:
      return PrimitiveType::kString;
    case google::api::expr::v1alpha1::Type::BYTES:
      return PrimitiveType::kBytes;
    default:
      return absl::InvalidArgumentError(
          "Illegal type specified for "
          "google::api::expr::v1alpha1::Type::PrimitiveType.");
  }
}

absl::StatusOr<WellKnownType> ToNative(
    google::api::expr::v1alpha1::Type::WellKnownType well_known_type) {
  switch (well_known_type) {
    case google::api::expr::v1alpha1::Type::WELL_KNOWN_TYPE_UNSPECIFIED:
      return WellKnownType::kWellKnownTypeUnspecified;
    case google::api::expr::v1alpha1::Type::ANY:
      return WellKnownType::kAny;
    case google::api::expr::v1alpha1::Type::TIMESTAMP:
      return WellKnownType::kTimestamp;
    case google::api::expr::v1alpha1::Type::DURATION:
      return WellKnownType::kDuration;
    default:
      return absl::InvalidArgumentError(
          "Illegal type specified for "
          "google::api::expr::v1alpha1::Type::WellKnownType.");
  }
}

absl::StatusOr<ListType> ToNative(
    const google::api::expr::v1alpha1::Type::ListType& list_type) {
  auto native_elem_type = ConvertProtoTypeToNative(list_type.elem_type());
  if (!native_elem_type.ok()) {
    return native_elem_type.status();
  }
  return ListType(std::make_unique<Type>(*(std::move(native_elem_type))));
}

absl::StatusOr<MapType> ToNative(
    const google::api::expr::v1alpha1::Type::MapType& map_type) {
  auto native_key_type = ConvertProtoTypeToNative(map_type.key_type());
  if (!native_key_type.ok()) {
    return native_key_type.status();
  }
  auto native_value_type = ConvertProtoTypeToNative(map_type.value_type());
  if (!native_value_type.ok()) {
    return native_value_type.status();
  }
  return MapType(std::make_unique<Type>(*(std::move(native_key_type))),
                 std::make_unique<Type>(*(std::move(native_value_type))));
}

absl::StatusOr<FunctionType> ToNative(
    const google::api::expr::v1alpha1::Type::FunctionType& function_type) {
  std::vector<Type> arg_types;
  arg_types.reserve(function_type.arg_types_size());
  for (const auto& arg_type : function_type.arg_types()) {
    auto native_arg = ConvertProtoTypeToNative(arg_type);
    if (!native_arg.ok()) {
      return native_arg.status();
    }
    arg_types.emplace_back(*(std::move(native_arg)));
  }
  auto native_result = ConvertProtoTypeToNative(function_type.result_type());
  if (!native_result.ok()) {
    return native_result.status();
  }
  return FunctionType(std::make_unique<Type>(*(std::move(native_result))),
                      std::move(arg_types));
}

absl::StatusOr<AbstractType> ToNative(
    const google::api::expr::v1alpha1::Type::AbstractType& abstract_type) {
  std::vector<Type> parameter_types;
  for (const auto& parameter_type : abstract_type.parameter_types()) {
    auto native_parameter_type = ConvertProtoTypeToNative(parameter_type);
    if (!native_parameter_type.ok()) {
      return native_parameter_type.status();
    }
    parameter_types.emplace_back(*(std::move(native_parameter_type)));
  }
  return AbstractType(abstract_type.name(), std::move(parameter_types));
}

absl::StatusOr<Type> ConvertProtoTypeToNative(
    const google::api::expr::v1alpha1::Type& type) {
  switch (type.type_kind_case()) {
    case google::api::expr::v1alpha1::Type::kDyn:
      return Type(DynamicType());
    case google::api::expr::v1alpha1::Type::kNull:
      return Type(NullValue::kNullValue);
    case google::api::expr::v1alpha1::Type::kPrimitive: {
      auto native_primitive = ToNative(type.primitive());
      if (!native_primitive.ok()) {
        return native_primitive.status();
      }
      return Type(*(std::move(native_primitive)));
    }
    case google::api::expr::v1alpha1::Type::kWrapper: {
      auto native_wrapper = ToNative(type.wrapper());
      if (!native_wrapper.ok()) {
        return native_wrapper.status();
      }
      return Type(PrimitiveTypeWrapper(*(std::move(native_wrapper))));
    }
    case google::api::expr::v1alpha1::Type::kWellKnown: {
      auto native_well_known = ToNative(type.well_known());
      if (!native_well_known.ok()) {
        return native_well_known.status();
      }
      return Type(*std::move(native_well_known));
    }
    case google::api::expr::v1alpha1::Type::kListType: {
      auto native_list_type = ToNative(type.list_type());
      if (!native_list_type.ok()) {
        return native_list_type.status();
      }
      return Type(*(std::move(native_list_type)));
    }
    case google::api::expr::v1alpha1::Type::kMapType: {
      auto native_map_type = ToNative(type.map_type());
      if (!native_map_type.ok()) {
        return native_map_type.status();
      }
      return Type(*(std::move(native_map_type)));
    }
    case google::api::expr::v1alpha1::Type::kFunction: {
      auto native_function = ToNative(type.function());
      if (!native_function.ok()) {
        return native_function.status();
      }
      return Type(*(std::move(native_function)));
    }
    case google::api::expr::v1alpha1::Type::kMessageType:
      return Type(MessageType(type.message_type()));
    case google::api::expr::v1alpha1::Type::kTypeParam:
      return Type(ParamType(type.type_param()));
    case google::api::expr::v1alpha1::Type::kType: {
      auto native_type = ConvertProtoTypeToNative(type.type());
      if (!native_type.ok()) {
        return native_type.status();
      }
      return Type(std::make_unique<Type>(*std::move(native_type)));
    }
    case google::api::expr::v1alpha1::Type::kError:
      return Type(ErrorType::kErrorTypeValue);
    case google::api::expr::v1alpha1::Type::kAbstractType: {
      auto native_abstract = ToNative(type.abstract_type());
      if (!native_abstract.ok()) {
        return native_abstract.status();
      }
      return Type(*(std::move(native_abstract)));
    }
    default:
      return absl::InvalidArgumentError(
          "Illegal type specified for google::api::expr::v1alpha1::Type.");
  }
}

absl::StatusOr<Reference> ConvertProtoReferenceToNative(
    const google::api::expr::v1alpha1::Reference& reference) {
  Reference ret_val;
  ret_val.set_name(reference.name());
  ret_val.mutable_overload_id().reserve(reference.overload_id_size());
  for (const auto& elem : reference.overload_id()) {
    ret_val.mutable_overload_id().emplace_back(elem);
  }
  if (reference.has_value()) {
    auto native_value = ConvertConstant(reference.value());
    if (!native_value.ok()) {
      return native_value.status();
    }
    ret_val.set_value(*(std::move(native_value)));
  }
  return ret_val;
}

absl::StatusOr<CheckedExpr> ConvertProtoCheckedExprToNative(
    const CheckedExprPb& checked_expr) {
  CheckedExpr ret_val;
  for (const auto& pair : checked_expr.reference_map()) {
    auto native_reference = ConvertProtoReferenceToNative(pair.second);
    if (!native_reference.ok()) {
      return native_reference.status();
    }
    ret_val.mutable_reference_map().emplace(pair.first,
                                            *(std::move(native_reference)));
  }
  for (const auto& pair : checked_expr.type_map()) {
    auto native_type = ConvertProtoTypeToNative(pair.second);
    if (!native_type.ok()) {
      return native_type.status();
    }
    ret_val.mutable_type_map().emplace(pair.first, *(std::move(native_type)));
  }
  auto native_source_info =
      ConvertProtoSourceInfoToNative(checked_expr.source_info());
  if (!native_source_info.ok()) {
    return native_source_info.status();
  }
  ret_val.set_source_info(*(std::move(native_source_info)));
  ret_val.set_expr_version(checked_expr.expr_version());
  auto native_checked_expr = ConvertProtoExprToNative(checked_expr.expr());
  if (!native_checked_expr.ok()) {
    return native_checked_expr.status();
  }
  ret_val.set_expr(*(std::move(native_checked_expr)));
  return ret_val;
}

}  // namespace internal

namespace {

using ::cel::ast_internal::AbstractType;
using ::cel::ast_internal::Bytes;
using ::cel::ast_internal::Call;
using ::cel::ast_internal::Comprehension;
using ::cel::ast_internal::Constant;
using ::cel::ast_internal::CreateList;
using ::cel::ast_internal::CreateStruct;
using ::cel::ast_internal::DynamicType;
using ::cel::ast_internal::ErrorType;
using ::cel::ast_internal::Expr;
using ::cel::ast_internal::FunctionType;
using ::cel::ast_internal::Ident;
using ::cel::ast_internal::ListType;
using ::cel::ast_internal::MapType;
using ::cel::ast_internal::MessageType;
using ::cel::ast_internal::NullValue;
using ::cel::ast_internal::ParamType;
using ::cel::ast_internal::PrimitiveType;
using ::cel::ast_internal::PrimitiveTypeWrapper;
using ::cel::ast_internal::Reference;
using ::cel::ast_internal::Select;
using ::cel::ast_internal::SourceInfo;
using ::cel::ast_internal::Type;
using ::cel::ast_internal::WellKnownType;

using ExprPb = google::api::expr::v1alpha1::Expr;
using ParsedExprPb = google::api::expr::v1alpha1::ParsedExpr;
using CheckedExprPb = google::api::expr::v1alpha1::CheckedExpr;
using SourceInfoPb = google::api::expr::v1alpha1::SourceInfo;
using ReferencePb = google::api::expr::v1alpha1::Reference;
using TypePb = google::api::expr::v1alpha1::Type;

struct ToProtoStackEntry {
  absl::Nonnull<const Expr*> source;
  absl::Nonnull<ExprPb*> dest;
};

absl::Status ConstantToProto(const ast_internal::Constant& source,
                             google::api::expr::v1alpha1::Constant& dest) {
  return absl::visit(cel::internal::Overloaded{
                         [&](NullValue) -> absl::Status {
                           dest.set_null_value(google::protobuf::NULL_VALUE);
                           return absl::OkStatus();
                         },
                         [&](bool value) {
                           dest.set_bool_value(value);
                           return absl::OkStatus();
                         },
                         [&](int64_t value) {
                           dest.set_int64_value(value);
                           return absl::OkStatus();
                         },
                         [&](uint64_t value) {
                           dest.set_uint64_value(value);
                           return absl::OkStatus();
                         },
                         [&](double value) {
                           dest.set_double_value(value);
                           return absl::OkStatus();
                         },
                         [&](const std::string& value) {
                           dest.set_string_value(value);
                           return absl::OkStatus();
                         },
                         [&](const Bytes& value) {
                           dest.set_bytes_value(value.bytes);
                           return absl::OkStatus();
                         },
                         [&](absl::Time time) {
                           return cel::internal::EncodeTime(
                               time, dest.mutable_timestamp_value());
                         },
                         [&](absl::Duration duration) {
                           return cel::internal::EncodeDuration(
                               duration, dest.mutable_duration_value());
                         }},
                     source.constant_kind());
}

struct ExprKindToProtoVisitor {
  absl::Status operator()(absl::monostate) { return absl::OkStatus(); }

  absl::Status operator()(const Ident& ident) {
    result->mutable_ident_expr()->set_name(ident.name());
    return absl::OkStatus();
  }

  absl::Status operator()(const Constant& constant) {
    return ConstantToProto(constant, *result->mutable_const_expr());
  }

  absl::Status operator()(const Select& select) {
    result->mutable_select_expr()->set_field(select.field());
    result->mutable_select_expr()->set_test_only(select.test_only());
    stack->push(
        {&select.operand(), result->mutable_select_expr()->mutable_operand()});
    return absl::OkStatus();
  }

  absl::Status operator()(const Call& call) {
    result->mutable_call_expr()->set_function(call.function());
    if (call.has_target()) {
      stack->push(
          {&call.target(), result->mutable_call_expr()->mutable_target()});
    }
    result->mutable_call_expr()->mutable_args()->Reserve(call.args().size());
    for (int i = 0; i < call.args().size(); ++i) {
      stack->push({&call.args()[i], result->mutable_call_expr()->add_args()});
    }
    return absl::OkStatus();
  }

  absl::Status operator()(const CreateList& create_list) {
    result->mutable_list_expr()->mutable_elements()->Reserve(
        create_list.elements().size());
    for (int i = 0; i < create_list.elements().size(); ++i) {
      stack->push({&create_list.elements()[i],
                   result->mutable_list_expr()->add_elements()});
    }
    result->mutable_list_expr()->mutable_optional_indices()->Reserve(
        create_list.optional_indices().size());
    for (int32_t index : create_list.optional_indices()) {
      result->mutable_list_expr()->add_optional_indices(index);
    }
    return absl::OkStatus();
  }

  absl::Status operator()(const Comprehension& comprehension) {
    auto* comprehension_pb = result->mutable_comprehension_expr();
    comprehension_pb->set_iter_var(comprehension.iter_var());
    comprehension_pb->set_accu_var(comprehension.accu_var());
    stack->push(
        {&comprehension.iter_range(), comprehension_pb->mutable_iter_range()});
    stack->push(
        {&comprehension.accu_init(), comprehension_pb->mutable_accu_init()});
    stack->push(
        {&comprehension.loop_step(), comprehension_pb->mutable_loop_step()});
    stack->push({&comprehension.loop_condition(),
                 comprehension_pb->mutable_loop_condition()});
    stack->push({&comprehension.result(), comprehension_pb->mutable_result()});
    return absl::OkStatus();
  }

  absl::Status operator()(const CreateStruct& create_struct) {
    auto* create_struct_pb = result->mutable_struct_expr();
    create_struct_pb->set_message_name(create_struct.message_name());
    create_struct_pb->mutable_entries()->Reserve(
        create_struct.entries().size());
    for (const CreateStruct::Entry& entry : create_struct.entries()) {
      auto* entry_pb = create_struct_pb->add_entries();
      entry_pb->set_id(entry.id());
      if (entry.has_map_key()) {
        stack->push({&entry.map_key(), entry_pb->mutable_map_key()});
      } else {
        entry_pb->set_field_key(entry.field_key());
      }
      stack->push({&entry.value(), entry_pb->mutable_value()});
      entry_pb->set_optional_entry(entry.optional_entry());
    }
    return absl::OkStatus();
  }

  ExprPb* result;
  std::stack<ToProtoStackEntry>* stack;
};

absl::Status ExprToProtoImpl(const Expr& expr,
                             std::stack<ToProtoStackEntry>& stack,
                             ExprPb* out) {
  out->set_id(expr.id());
  CEL_RETURN_IF_ERROR(
      absl::visit(ExprKindToProtoVisitor{out, &stack}, expr.expr_kind()));
  return absl::OkStatus();
}

absl::StatusOr<ExprPb> ExprToProto(const Expr& expr) {
  std::stack<ToProtoStackEntry> conversion_stack;
  int iterations = 0;
  ExprPb proto_expr;
  conversion_stack.push({&expr, &proto_expr});
  while (!conversion_stack.empty()) {
    ToProtoStackEntry entry = conversion_stack.top();
    conversion_stack.pop();
    CEL_RETURN_IF_ERROR(
        ExprToProtoImpl(*entry.source, conversion_stack, entry.dest));
    ++iterations;
    if (iterations > kMaxIterations) {
      return absl::InternalError(
          "max iterations exceeded in native to proto ast conversion.");
    }
  }
  return proto_expr;
}

absl::StatusOr<SourceInfoPb> SourceInfoToProto(const SourceInfo& source_info) {
  SourceInfoPb result;
  result.set_syntax_version(source_info.syntax_version());
  result.set_location(source_info.location());

  for (int32_t line_offset : source_info.line_offsets()) {
    result.add_line_offsets(line_offset);
  }

  for (auto pos_iter = source_info.positions().begin();
       pos_iter != source_info.positions().end(); ++pos_iter) {
    (*result.mutable_positions())[pos_iter->first] = pos_iter->second;
  }

  for (auto macro_iter = source_info.macro_calls().begin();
       macro_iter != source_info.macro_calls().end(); ++macro_iter) {
    ExprPb& dest_macro = (*result.mutable_macro_calls())[macro_iter->first];
    CEL_ASSIGN_OR_RETURN(dest_macro, ExprToProto(macro_iter->second));
  }

  return result;
}

absl::StatusOr<ReferencePb> ReferenceToProto(const Reference& reference) {
  ReferencePb result;

  result.set_name(reference.name());

  for (const auto& overload_id : reference.overload_id()) {
    result.add_overload_id(overload_id);
  }

  if (reference.has_value()) {
    CEL_RETURN_IF_ERROR(
        ConstantToProto(reference.value(), *result.mutable_value()));
  }

  return result;
}

absl::Status TypeToProto(const Type& type, TypePb* result);

struct TypeKindToProtoVisitor {
  absl::Status operator()(PrimitiveType primitive) {
    switch (primitive) {
      case PrimitiveType::kPrimitiveTypeUnspecified:
        result->set_primitive(TypePb::PRIMITIVE_TYPE_UNSPECIFIED);
        return absl::OkStatus();
      case PrimitiveType::kBool:
        result->set_primitive(TypePb::BOOL);
        return absl::OkStatus();
      case PrimitiveType::kInt64:
        result->set_primitive(TypePb::INT64);
        return absl::OkStatus();
      case PrimitiveType::kUint64:
        result->set_primitive(TypePb::UINT64);
        return absl::OkStatus();
      case PrimitiveType::kDouble:
        result->set_primitive(TypePb::DOUBLE);
        return absl::OkStatus();
      case PrimitiveType::kString:
        result->set_primitive(TypePb::STRING);
        return absl::OkStatus();
      case PrimitiveType::kBytes:
        result->set_primitive(TypePb::BYTES);
        return absl::OkStatus();
      default:
        break;
    }
    return absl::InvalidArgumentError("Unsupported primitive type");
  }

  absl::Status operator()(PrimitiveTypeWrapper wrapper) {
    CEL_RETURN_IF_ERROR(this->operator()(wrapper.type()));
    auto wrapped = result->primitive();
    result->set_wrapper(wrapped);
    return absl::OkStatus();
  }

  absl::Status operator()(DynamicType) {
    result->mutable_dyn();
    return absl::OkStatus();
  }

  absl::Status operator()(ErrorType) {
    result->mutable_error();
    return absl::OkStatus();
  }

  absl::Status operator()(NullValue) {
    result->set_null(google::protobuf::NULL_VALUE);
    return absl::OkStatus();
  }

  absl::Status operator()(const ListType& list_type) {
    return TypeToProto(list_type.elem_type(),
                       result->mutable_list_type()->mutable_elem_type());
  }

  absl::Status operator()(const MapType& map_type) {
    CEL_RETURN_IF_ERROR(TypeToProto(
        map_type.key_type(), result->mutable_map_type()->mutable_key_type()));
    return TypeToProto(map_type.value_type(),
                       result->mutable_map_type()->mutable_value_type());
  }

  absl::Status operator()(const MessageType& message_type) {
    result->set_message_type(message_type.type());
    return absl::OkStatus();
  }

  absl::Status operator()(const WellKnownType& well_known_type) {
    switch (well_known_type) {
      case WellKnownType::kWellKnownTypeUnspecified:
        result->set_well_known(TypePb::WELL_KNOWN_TYPE_UNSPECIFIED);
        return absl::OkStatus();
      case WellKnownType::kAny:
        result->set_well_known(TypePb::ANY);
        return absl::OkStatus();

      case WellKnownType::kDuration:
        result->set_well_known(TypePb::DURATION);
        return absl::OkStatus();
      case WellKnownType::kTimestamp:
        result->set_well_known(TypePb::TIMESTAMP);
        return absl::OkStatus();
      default:
        break;
    }
    return absl::InvalidArgumentError("Unsupported well-known type");
  }

  absl::Status operator()(const FunctionType& function_type) {
    CEL_RETURN_IF_ERROR(
        TypeToProto(function_type.result_type(),
                    result->mutable_function()->mutable_result_type()));

    for (const Type& arg_type : function_type.arg_types()) {
      CEL_RETURN_IF_ERROR(
          TypeToProto(arg_type, result->mutable_function()->add_arg_types()));
    }
    return absl::OkStatus();
  }

  absl::Status operator()(const AbstractType& type) {
    auto* abstract_type_pb = result->mutable_abstract_type();
    abstract_type_pb->set_name(type.name());
    for (const Type& type_param : type.parameter_types()) {
      CEL_RETURN_IF_ERROR(
          TypeToProto(type_param, abstract_type_pb->add_parameter_types()));
    }
    return absl::OkStatus();
  }

  absl::Status operator()(const std::unique_ptr<Type>& type_type) {
    return TypeToProto(*type_type, result->mutable_type());
  }

  absl::Status operator()(const ParamType& param_type) {
    result->set_type_param(param_type.type());
    return absl::OkStatus();
  }

  TypePb* result;
};

absl::Status TypeToProto(const Type& type, TypePb* result) {
  return absl::visit(TypeKindToProtoVisitor{result}, type.type_kind());
}

}  // namespace

absl::StatusOr<std::unique_ptr<Ast>> CreateAstFromParsedExpr(
    const google::api::expr::v1alpha1::Expr& expr,
    const google::api::expr::v1alpha1::SourceInfo* source_info) {
  CEL_ASSIGN_OR_RETURN(auto runtime_expr,
                       internal::ConvertProtoExprToNative(expr));
  cel::ast_internal::SourceInfo runtime_source_info;
  if (source_info != nullptr) {
    CEL_ASSIGN_OR_RETURN(
        runtime_source_info,
        internal::ConvertProtoSourceInfoToNative(*source_info));
  }
  return std::make_unique<cel::ast_internal::AstImpl>(
      std::move(runtime_expr), std::move(runtime_source_info));
}

absl::StatusOr<std::unique_ptr<Ast>> CreateAstFromParsedExpr(
    const ParsedExprPb& parsed_expr) {
  CEL_ASSIGN_OR_RETURN(cel::ast_internal::ParsedExpr expr,
                       internal::ConvertProtoParsedExprToNative(parsed_expr));
  return std::make_unique<cel::ast_internal::AstImpl>(std::move(expr));
}

absl::StatusOr<ParsedExprPb> CreateParsedExprFromAst(const Ast& ast) {
  const auto& ast_impl = ast_internal::AstImpl::CastFromPublicAst(ast);
  ParsedExprPb parsed_expr;
  CEL_ASSIGN_OR_RETURN(*parsed_expr.mutable_expr(),
                       ExprToProto(ast_impl.root_expr()));
  CEL_ASSIGN_OR_RETURN(*parsed_expr.mutable_source_info(),
                       SourceInfoToProto(ast_impl.source_info()));

  return parsed_expr;
}

absl::StatusOr<std::unique_ptr<Ast>> CreateAstFromCheckedExpr(
    const CheckedExprPb& checked_expr) {
  CEL_ASSIGN_OR_RETURN(cel::ast_internal::CheckedExpr expr,
                       internal::ConvertProtoCheckedExprToNative(checked_expr));
  return std::make_unique<cel::ast_internal::AstImpl>(std::move(expr));
}

absl::StatusOr<google::api::expr::v1alpha1::CheckedExpr> CreateCheckedExprFromAst(
    const Ast& ast) {
  if (!ast.IsChecked()) {
    return absl::InvalidArgumentError("AST is not type-checked");
  }
  const auto& ast_impl = ast_internal::AstImpl::CastFromPublicAst(ast);
  CheckedExprPb checked_expr;
  checked_expr.set_expr_version(ast_impl.expr_version());
  CEL_ASSIGN_OR_RETURN(*checked_expr.mutable_expr(),
                       ExprToProto(ast_impl.root_expr()));
  CEL_ASSIGN_OR_RETURN(*checked_expr.mutable_source_info(),
                       SourceInfoToProto(ast_impl.source_info()));
  for (auto it = ast_impl.reference_map().begin();
       it != ast_impl.reference_map().end(); ++it) {
    ReferencePb& dest_reference =
        (*checked_expr.mutable_reference_map())[it->first];
    CEL_ASSIGN_OR_RETURN(dest_reference, ReferenceToProto(it->second));
  }

  for (auto it = ast_impl.type_map().begin(); it != ast_impl.type_map().end();
       ++it) {
    TypePb& dest_type = (*checked_expr.mutable_type_map())[it->first];
    CEL_RETURN_IF_ERROR(TypeToProto(it->second, &dest_type));
  }

  return checked_expr;
}

}  // namespace cel::extensions
