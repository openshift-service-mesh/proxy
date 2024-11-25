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

#include "extensions/select_optimization.h"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "absl/types/variant.h"
#include "base/ast_internal/ast_impl.h"
#include "base/ast_internal/expr.h"
#include "base/attribute.h"
#include "base/builtins.h"
#include "base/handle.h"
#include "base/memory.h"
#include "base/type.h"
#include "base/type_factory.h"
#include "base/types/struct_type.h"
#include "base/value_factory.h"
#include "base/values/error_value.h"
#include "base/values/map_value.h"
#include "base/values/struct_value.h"
#include "base/values/unknown_value.h"
#include "common/kind.h"
#include "eval/compiler/flat_expr_builder_extensions.h"
#include "eval/eval/attribute_trail.h"
#include "eval/eval/evaluator_core.h"
#include "eval/eval/expression_step_base.h"
#include "eval/public/ast_rewrite_native.h"
#include "eval/public/source_position_native.h"
#include "internal/overloaded.h"
#include "internal/status_macros.h"
#include "runtime/internal/errors.h"
#include "runtime/runtime_options.h"

namespace cel::extensions {
namespace {

using ::cel::ast_internal::AstImpl;
using ::cel::ast_internal::AstRewriterBase;
using ::cel::ast_internal::Call;
using ::cel::ast_internal::ConstantKind;
using ::cel::ast_internal::Expr;
using ::cel::ast_internal::ExprKind;
using ::cel::ast_internal::Select;
using ::cel::ast_internal::SourcePosition;
using ::google::api::expr::runtime::AttributeTrail;
using ::google::api::expr::runtime::ExecutionFrame;
using ::google::api::expr::runtime::ExpressionStepBase;
using ::google::api::expr::runtime::PlannerContext;
using ::google::api::expr::runtime::ProgramOptimizer;

// Represents a single select operation (field access or indexing).
// For struct-typed field accesses, includes the field name and the field
// number.
struct SelectInstruction {
  int64_t number;
  // backed by the underlying type.
  absl::string_view name;
};

// Represents a single qualifier in a traversal path.
// TODO(uncreated-issue/51): support variable indexes.
using QualifierInstruction =
    absl::variant<SelectInstruction, std::string, int64_t, uint64_t, bool>;

struct SelectPath {
  Expr* operand;
  std::vector<QualifierInstruction> select_instructions;
  bool test_only;
  // TODO(uncreated-issue/54): support for optionals.
};

// Generates the AST representation of the qualification path for the optimized
// select branch. I.e., the list-typed second argument of the @cel.attribute
// call.
Expr MakeSelectPathExpr(
    const std::vector<QualifierInstruction>& select_instructions) {
  Expr result;
  auto& ast_list = result.mutable_list_expr().mutable_elements();
  ast_list.reserve(select_instructions.size());
  cel::internal::Overloaded visitor{
      [&](const SelectInstruction& instruction) {
        Expr ast_instruction;
        Expr field_number;
        field_number.mutable_const_expr().set_int64_value(instruction.number);
        Expr field_name;
        field_name.mutable_const_expr().set_string_value(
            std::string(instruction.name));
        auto& field_specifier =
            ast_instruction.mutable_list_expr().mutable_elements();
        field_specifier.push_back(std::move(field_number));
        field_specifier.push_back(std::move(field_name));

        ast_list.push_back(std::move(ast_instruction));
      },
      [&](absl::string_view instruction) {
        Expr const_expr;
        const_expr.mutable_const_expr().set_string_value(
            std::string(instruction));
        ast_list.push_back(std::move(const_expr));
      },
      [&](int64_t instruction) {
        Expr const_expr;
        const_expr.mutable_const_expr().set_int64_value(instruction);
        ast_list.push_back(std::move(const_expr));
      },
      [&](uint64_t instruction) {
        Expr const_expr;
        const_expr.mutable_const_expr().set_uint64_value(instruction);
        ast_list.push_back(std::move(const_expr));
      },
      [&](bool instruction) {
        Expr const_expr;
        const_expr.mutable_const_expr().set_bool_value(instruction);
        ast_list.push_back(std::move(const_expr));
      }};

  for (const auto& instruction : select_instructions) {
    absl::visit(visitor, instruction);
  }
  return result;
}

// Returns a single select operation based on the inferred type of the operand
// and the field name. If the operand type doesn't define the field, returns
// nullopt.
absl::optional<SelectInstruction> GetSelectInstruction(
    const StructType& runtime_type, PlannerContext& planner_context,
    absl::string_view field_name) {
  auto field_or =
      runtime_type
          .FindFieldByName(planner_context.value_factory().type_manager(),
                           field_name)
          .value_or(absl::nullopt);
  if (field_or.has_value()) {
    return SelectInstruction{field_or->number, field_or->name};
  }
  return absl::nullopt;
}

absl::StatusOr<SelectQualifier> SelectQualifierFromList(
    const ast_internal::CreateList& list) {
  if (list.elements().size() != 2) {
    return absl::InvalidArgumentError("Invalid cel.attribute select list");
  }

  const Expr& field_number = list.elements()[0];
  const Expr& field_name = list.elements()[1];

  if (!field_number.has_const_expr() ||
      !field_number.const_expr().has_int64_value()) {
    return absl::InvalidArgumentError(
        "Invalid cel.attribute field select number");
  }

  if (!field_name.has_const_expr() ||
      !field_name.const_expr().has_string_value()) {
    return absl::InvalidArgumentError(
        "Invalid cel.attribute field select name");
  }

  return FieldSpecifier{field_number.const_expr().int64_value(),
                        field_name.const_expr().string_value()};
}

absl::StatusOr<QualifierInstruction> SelectInstructionFromConstant(
    const ast_internal::Constant& constant) {
  if (constant.has_int64_value()) {
    return QualifierInstruction(constant.int64_value());
  } else if (constant.has_uint64_value()) {
    return QualifierInstruction(constant.uint64_value());
  } else if (constant.has_bool_value()) {
    return QualifierInstruction(constant.bool_value());
  } else if (constant.has_string_value()) {
    return QualifierInstruction(constant.string_value());
  }

  return absl::InvalidArgumentError("Invalid cel.attribute constant");
}

absl::StatusOr<SelectQualifier> SelectQualifierFromConstant(
    const ast_internal::Constant& constant) {
  if (constant.has_int64_value()) {
    return AttributeQualifier::OfInt(constant.int64_value());
  } else if (constant.has_uint64_value()) {
    return AttributeQualifier::OfUint(constant.uint64_value());
  } else if (constant.has_bool_value()) {
    return AttributeQualifier::OfBool(constant.bool_value());
  } else if (constant.has_string_value()) {
    return AttributeQualifier::OfString(constant.string_value());
  }

  return absl::InvalidArgumentError("Invalid cel.attribute constant");
}

absl::StatusOr<size_t> ListIndexFromQualifier(const AttributeQualifier& qual) {
  int64_t value = -1;
  switch (qual.kind()) {
    case Kind::kInt:
      value = *qual.GetInt64Key();
      break;
    default:
      // TODO(uncreated-issue/51): type-checker will reject an unsigned literal, but
      // should be supported as a dyn / variable.
      return runtime_internal::CreateNoMatchingOverloadError(
          cel::builtin::kIndex);
  }

  if (value < 0) {
    return absl::InvalidArgumentError("list index less than 0");
  }

  return static_cast<size_t>(value);
}

absl::StatusOr<Handle<Value>> MapKeyFromQualifier(
    const AttributeQualifier& qual, ValueFactory& factory) {
  switch (qual.kind()) {
    case Kind::kInt:
      return factory.CreateIntValue(*qual.GetInt64Key());
    case Kind::kUint:
      return factory.CreateUintValue(*qual.GetUint64Key());
    case Kind::kBool:
      return factory.CreateBoolValue(*qual.GetBoolKey());
    case Kind::kString:
      return factory.CreateStringValue(*qual.GetStringKey());
    default:
      return runtime_internal::CreateNoMatchingOverloadError(
          cel::builtin::kIndex);
  }
}

absl::StatusOr<Handle<Value>> ApplyQualifier(const Value& operand,
                                             const SelectQualifier& qualifier,
                                             ValueFactory& value_factory) {
  return absl::visit(
      cel::internal::Overloaded{
          [&](const FieldSpecifier& field_specifier)
              -> absl::StatusOr<Handle<Value>> {
            if (!operand.Is<StructValue>()) {
              return value_factory.CreateErrorValue(
                  cel::runtime_internal::CreateNoMatchingOverloadError(
                      "<select>"));
            }
            return operand.As<StructValue>().GetFieldByName(
                value_factory, field_specifier.name);
          },
          [&](const AttributeQualifier& qualifier)
              -> absl::StatusOr<Handle<Value>> {
            if (operand.Is<ListValue>()) {
              auto index_or = ListIndexFromQualifier(qualifier);
              if (!index_or.ok()) {
                return value_factory.CreateErrorValue(index_or.status());
              }
              return operand.As<ListValue>().Get(value_factory, *index_or);
            } else if (operand.Is<MapValue>()) {
              auto key_or = MapKeyFromQualifier(qualifier, value_factory);
              if (!key_or.ok()) {
                return value_factory.CreateErrorValue(key_or.status());
              }
              return operand.As<MapValue>().Get(value_factory, *key_or);
            }
            return value_factory.CreateErrorValue(
                cel::runtime_internal::CreateNoMatchingOverloadError(
                    cel::builtin::kIndex));
          }},
      qualifier);
}

absl::StatusOr<Handle<Value>> FallbackSelect(
    const Value& root, absl::Span<const SelectQualifier> select_path,
    bool presence_test, ValueFactory& value_factory) {
  const Value* elem = &root;
  Handle<Value> result;

  for (const auto& instruction :
       select_path.subspan(0, select_path.size() - 1)) {
    CEL_ASSIGN_OR_RETURN(result,
                         ApplyQualifier(*elem, instruction, value_factory));
    if (result->Is<ErrorValue>()) {
      return result;
    }
    elem = &(*result);
  }

  const auto& last_instruction = select_path.back();
  if (presence_test) {
    return absl::visit(
        cel::internal::Overloaded{
            [&](const FieldSpecifier& field_specifier)
                -> absl::StatusOr<Handle<Value>> {
              if (!elem->Is<StructValue>()) {
                return value_factory.CreateErrorValue(
                    cel::runtime_internal::CreateNoMatchingOverloadError(
                        "<select>"));
              }
              CEL_ASSIGN_OR_RETURN(
                  bool present,
                  elem->As<StructValue>().HasFieldByName(
                      value_factory.type_manager(), field_specifier.name));
              return value_factory.CreateBoolValue(present);
            },
            [&](const AttributeQualifier& qualifier)
                -> absl::StatusOr<Handle<Value>> {
              if (!elem->Is<MapValue>() || qualifier.kind() != Kind::kString) {
                return value_factory.CreateErrorValue(
                    cel::runtime_internal::CreateNoMatchingOverloadError(
                        "has"));
              }

              return elem->As<MapValue>().Has(
                  value_factory, value_factory.CreateUncheckedStringValue(
                                     std::string(*qualifier.GetStringKey())));
            }},
        last_instruction);
  }

  return ApplyQualifier(*elem, last_instruction, value_factory);
}

absl::StatusOr<std::vector<SelectQualifier>> SelectInstructionsFromCall(
    const ast_internal::Call& call) {
  if (call.args().size() < 2 || !call.args()[1].has_list_expr()) {
    return absl::InvalidArgumentError("Invalid cel.attribute call");
  }
  std::vector<SelectQualifier> instructions;
  const auto& ast_path = call.args()[1].list_expr().elements();
  instructions.reserve(ast_path.size());

  for (const Expr& element : ast_path) {
    // Optimized field select.
    if (element.has_list_expr()) {
      CEL_ASSIGN_OR_RETURN(instructions.emplace_back(),
                           SelectQualifierFromList(element.list_expr()));
    } else if (element.has_const_expr()) {
      CEL_ASSIGN_OR_RETURN(instructions.emplace_back(),
                           SelectQualifierFromConstant(element.const_expr()));
    } else {
      return absl::InvalidArgumentError("Invalid cel.attribute call");
    }
  }

  // TODO(uncreated-issue/54): support for optionals.

  return instructions;
}

class RewriterImpl : public AstRewriterBase {
 public:
  RewriterImpl(const AstImpl& ast, PlannerContext& planner_context)
      : ast_(ast),
        planner_context_(planner_context),
        type_factory_(MemoryManagerRef::ReferenceCounting()) {}

  void PreVisitExpr(const Expr* expr, const SourcePosition* position) override {
    path_.push_back(expr);
  }

  void PreVisitSelect(const Select* select, const Expr* expr,
                      const SourcePosition*) override {
    const Expr& operand = select->operand();
    const std::string& field_name = select->field();
    // Select optimization can generalize to lists and maps, but for now only
    // support message traversal.
    const ast_internal::Type& checker_type = ast_.GetType(operand.id());

    absl::optional<Handle<Type>> rt_type =
        (checker_type.has_message_type())
            ? GetRuntimeType(checker_type.message_type().type())
            : absl::nullopt;
    if (rt_type.has_value() && (*rt_type)->Is<StructType>()) {
      const StructType& runtime_type = (*rt_type)->As<StructType>();
      absl::optional<SelectInstruction> field_or =
          GetSelectInstruction(runtime_type, planner_context_, field_name);
      if (field_or.has_value()) {
        candidates_[expr] = std::move(field_or).value();
      }
    } else if (checker_type.has_map_type()) {
      candidates_[expr] = QualifierInstruction(field_name);
    }
    // else
    // TODO(uncreated-issue/54): add support for either dyn or any. Excluded to
    // simplify program plan.
  }

  void PreVisitCall(const Call* call, const Expr* expr,
                    const SourcePosition*) override {
    if (call->args().size() != 2 ||
        call->function() != ::cel::builtin::kIndex) {
      return;
    }

    const auto& qualifier_expr = call->args()[1];
    if (qualifier_expr.has_const_expr()) {
      auto qualifier_or =
          SelectInstructionFromConstant(qualifier_expr.const_expr());
      if (!qualifier_or.ok()) {
        SetProgressStatus(qualifier_or.status());
        return;
      }
      candidates_[expr] = std::move(qualifier_or).value();
    }
    // TODO(uncreated-issue/54): support variable indexes
  }

  bool PostVisitRewrite(Expr* expr, const SourcePosition* position) override {
    if (!progress_status_.ok()) {
      return false;
    }
    path_.pop_back();
    auto candidate_iter = candidates_.find(expr);
    if (candidate_iter == candidates_.end()) {
      return false;
    }

    // On post visit, filter candidates that aren't rooted on a message or a
    // select chain.
    const QualifierInstruction& candidate = candidate_iter->second;
    if (!HasOptimizeableRoot(expr, candidate)) {
      candidates_.erase(candidate_iter);
      return false;
    }

    if (!path_.empty() && candidates_.find(path_.back()) != candidates_.end()) {
      // parent is optimizeable, defer rewriting until we consider the parent.
      return false;
    }

    SelectPath path = GetSelectPath(expr);

    // generate the new cel.attribute call.
    absl::string_view fn = path.test_only ? kFieldsHas : kCelAttribute;

    Expr operand(std::move(*path.operand));
    Expr call;
    call.set_id(expr->id());
    call.mutable_call_expr().set_function(std::string(fn));
    call.mutable_call_expr().mutable_args().reserve(2);

    call.mutable_call_expr().mutable_args().push_back(std::move(operand));
    call.mutable_call_expr().mutable_args().push_back(
        MakeSelectPathExpr(path.select_instructions));

    // TODO(uncreated-issue/54): support for optionals.
    *expr = std::move(call);

    return true;
  }

  absl::Status GetProgressStatus() const { return progress_status_; }

 private:
  SelectPath GetSelectPath(Expr* expr) {
    SelectPath result;
    result.test_only = false;
    Expr* operand = expr;
    auto candidate_iter = candidates_.find(operand);
    while (candidate_iter != candidates_.end()) {
      result.select_instructions.push_back(candidate_iter->second);
      if (operand->has_select_expr()) {
        if (operand->select_expr().test_only()) {
          result.test_only = true;
        }
        operand = &(operand->mutable_select_expr().mutable_operand());
      } else {
        ABSL_DCHECK(operand->has_call_expr());
        operand = &(operand->mutable_call_expr().mutable_args()[0]);
      }
      candidate_iter = candidates_.find(operand);
    }
    absl::c_reverse(result.select_instructions);
    result.operand = operand;
    return result;
  }

  // Check whether the candidate has a message type as a root (the operand for
  // the batched select operation).
  // Called on post visit.
  bool HasOptimizeableRoot(const Expr* expr,
                           const QualifierInstruction& candidate) {
    if (absl::holds_alternative<SelectInstruction>(candidate)) {
      return true;
    }
    const Expr* operand = nullptr;
    if (expr->has_call_expr() && expr->call_expr().args().size() == 2 &&
        expr->call_expr().function() == ::cel::builtin::kIndex) {
      operand = &expr->call_expr().args()[0];
    } else if (expr->has_select_expr()) {
      operand = &expr->select_expr().operand();
    }

    if (operand == nullptr) {
      return false;
    }

    return candidates_.find(operand) != candidates_.end();
  }

  absl::optional<Handle<Type>> GetRuntimeType(absl::string_view type_name) {
    return planner_context_.value_factory()
        .type_manager()
        .ResolveType(type_name)
        .value_or(absl::nullopt);
  }

  void SetProgressStatus(const absl::Status& status) {
    if (progress_status_.ok() && !status.ok()) {
      progress_status_ = status;
    }
  }

  const AstImpl& ast_;
  PlannerContext& planner_context_;
  TypeFactory type_factory_;
  // ids of potentially optimizeable expr nodes.
  absl::flat_hash_map<const Expr*, QualifierInstruction> candidates_;
  std::vector<const Expr*> path_;
  absl::Status progress_status_;
};

class OptimizedSelectStep : public ExpressionStepBase {
 public:
  OptimizedSelectStep(int expr_id, absl::optional<Attribute> attribute,
                      std::vector<SelectQualifier> select_path,
                      std::vector<AttributeQualifier> qualifiers,
                      bool presence_test,
                      bool enable_wrapper_type_null_unboxing,
                      SelectOptimizationOptions options)
      : ExpressionStepBase(expr_id),
        attribute_(std::move(attribute)),
        select_path_(std::move(select_path)),
        qualifiers_(std::move(qualifiers)),
        presence_test_(presence_test),
        enable_wrapper_type_null_unboxing_(enable_wrapper_type_null_unboxing),
        options_(options)

  {
    ABSL_DCHECK(!select_path_.empty());
  }

  absl::Status Evaluate(ExecutionFrame* frame) const override;

 private:
  absl::StatusOr<Handle<Value>> ApplySelect(
      ExecutionFrame* frame, const StructValue& struct_value) const;

  // Get the effective attribute for the optimized select expression.
  // Assumes the operand is the top of stack if the attribute wasn't known at
  // plan time.
  AttributeTrail GetAttributeTrail(ExecutionFrame* frame) const;

  absl::optional<Attribute> attribute_;
  std::vector<SelectQualifier> select_path_;
  std::vector<AttributeQualifier> qualifiers_;
  bool presence_test_;
  bool enable_wrapper_type_null_unboxing_;
  SelectOptimizationOptions options_;
};

// Check for unknowns or missing attributes.
absl::StatusOr<absl::optional<Handle<Value>>> CheckForMarkedAttributes(
    ExecutionFrame* frame, const AttributeTrail& attribute_trail) {
  if (attribute_trail.empty()) {
    return absl::nullopt;
  }

  if (frame->enable_unknowns()) {
    // Check if the inferred attribute is marked. Only matches if this attribute
    // or a parent is marked unknown (use_partial = false).
    // Partial matches (i.e. descendant of this attribute is marked) aren't
    // considered yet in case another operation would select an unmarked
    // descended attribute.
    //
    // TODO(uncreated-issue/51): this may return a more specific attribute than the
    // declared pattern. Follow up will truncate the returned attribute to match
    // the pattern.
    if (frame->attribute_utility().CheckForUnknown(attribute_trail,
                                                   /*use_partial=*/false)) {
      return frame->attribute_utility().CreateUnknownSet(
          attribute_trail.attribute());
    }
  }
  if (frame->enable_missing_attribute_errors()) {
    if (frame->attribute_utility().CheckForMissingAttribute(attribute_trail)) {
      return frame->attribute_utility().CreateMissingAttributeError(
          attribute_trail.attribute());
    }
  }

  return absl::nullopt;
}

AttributeTrail OptimizedSelectStep::GetAttributeTrail(
    ExecutionFrame* frame) const {
  if (attribute_.has_value()) {
    return AttributeTrail(*attribute_);
  }

  auto attr = frame->value_stack().PeekAttribute();
  std::vector<AttributeQualifier> qualifiers =
      std::vector<AttributeQualifier>(attr.attribute().qualifier_path().begin(),
                                      attr.attribute().qualifier_path().end());
  qualifiers.reserve(qualifiers_.size() + qualifiers.size());
  absl::c_copy(qualifiers_, std::back_inserter(qualifiers));
  AttributeTrail result(Attribute(std::string(attr.attribute().variable_name()),
                                  std::move(qualifiers)));
  return result;
}

absl::StatusOr<Handle<Value>> OptimizedSelectStep::ApplySelect(
    ExecutionFrame* frame, const StructValue& struct_value) const {
  absl::StatusOr<QualifyResult> value_or =
      (options_.force_fallback_implementation)
          ? absl::UnimplementedError("Forced fallback impl")
          : struct_value.Qualify(frame->value_factory(), select_path_,
                                 presence_test_);

  if (!value_or.ok()) {
    if (value_or.status().code() == absl::StatusCode::kUnimplemented) {
      return FallbackSelect(struct_value, select_path_, presence_test_,
                            frame->value_factory());
    }

    return value_or.status();
  }

  if (value_or->qualifier_count < 0 ||
      value_or->qualifier_count >= select_path_.size()) {
    return std::move(value_or->value);
  }

  return FallbackSelect(
      *value_or->value,
      absl::MakeConstSpan(select_path_).subspan(value_or->qualifier_count),
      presence_test_, frame->value_factory());
}

absl::Status OptimizedSelectStep::Evaluate(ExecutionFrame* frame) const {
  // Default empty.
  AttributeTrail attribute_trail;
  // TODO(uncreated-issue/51): add support for variable qualifiers and string literal
  // variable names.
  constexpr size_t kStackInputs = 1;

  if (frame->enable_attribute_tracking()) {
    // Compute the attribute trail then check for any marked values.
    // When possible, this is computed at plan time based on the optimized
    // select arguments.
    // TODO(uncreated-issue/51): add support variable qualifiers
    attribute_trail = GetAttributeTrail(frame);
    CEL_ASSIGN_OR_RETURN(absl::optional<Handle<Value>> value,
                         CheckForMarkedAttributes(frame, attribute_trail));
    if (value.has_value()) {
      frame->value_stack().Pop(kStackInputs);
      frame->value_stack().Push(std::move(value).value(),
                                std::move(attribute_trail));
      return absl::OkStatus();
    }
  }

  // Otherwise, we expect the operand to be top of stack.
  const Handle<Value>& operand = frame->value_stack().Peek();

  if (operand->Is<ErrorValue>() || operand->Is<UnknownValue>()) {
    // Just forward the error which is already top of stack.
    return absl::OkStatus();
  }

  if (!operand->Is<StructValue>()) {
    return absl::InvalidArgumentError(
        "Expected struct type for select optimization.");
  }

  CEL_ASSIGN_OR_RETURN(Handle<Value> result,
                       ApplySelect(frame, operand->As<StructValue>()));

  frame->value_stack().Pop(kStackInputs);
  frame->value_stack().Push(std::move(result), std::move(attribute_trail));
  return absl::OkStatus();
}

class SelectOptimizer : public ProgramOptimizer {
 public:
  explicit SelectOptimizer(const SelectOptimizationOptions& options)
      : options_(options) {}

  absl::Status OnPreVisit(PlannerContext& context,
                          const cel::ast_internal::Expr& node) override {
    return absl::OkStatus();
  }

  absl::Status OnPostVisit(PlannerContext& context,
                           const cel::ast_internal::Expr& node) override;

 private:
  SelectOptimizationOptions options_;
};

absl::Status SelectOptimizer::OnPostVisit(PlannerContext& context,
                                          const cel::ast_internal::Expr& node) {
  if (!node.has_call_expr()) {
    return absl::OkStatus();
  }

  absl::string_view fn = node.call_expr().function();
  if (fn != kFieldsHas && fn != kCelAttribute) {
    return absl::OkStatus();
  }

  if (node.call_expr().args().size() < 2 ||
      node.call_expr().args().size() > 3) {
    return absl::InvalidArgumentError("Invalid cel.attribute call");
  }

  if (node.call_expr().args().size() == 3) {
    return absl::UnimplementedError("Optionals not yet supported");
  }

  CEL_ASSIGN_OR_RETURN(std::vector<SelectQualifier> instructions,
                       SelectInstructionsFromCall(node.call_expr()));

  if (instructions.empty()) {
    return absl::InvalidArgumentError("Invalid cel.attribute no select steps.");
  }

  bool presence_test = false;

  if (fn == kFieldsHas) {
    presence_test = true;
  }

  const Expr& operand = node.call_expr().args()[0];
  absl::optional<Attribute> attribute;
  absl::string_view identifier;
  if (operand.has_ident_expr()) {
    identifier = operand.ident_expr().name();
  }

  if (absl::StrContains(identifier, ".")) {
    return absl::UnimplementedError("qualified identifiers not supported.");
  }

  std::vector<AttributeQualifier> qualifiers;
  qualifiers.reserve(instructions.size());
  for (const auto& instruction : instructions) {
    qualifiers.push_back(
        absl::visit(cel::internal::Overloaded{
                        [](const FieldSpecifier& field) {
                          return AttributeQualifier::OfString(field.name);
                        },
                        [](const AttributeQualifier& q) { return q; }},
                    instruction));
  }

  if (!identifier.empty()) {
    attribute.emplace(std::string(identifier), qualifiers);
  }

  // TODO(uncreated-issue/51): If the first argument is a string literal, the custom
  // step needs to handle variable lookup.
  google::api::expr::runtime::ExecutionPath path;

  // else, we need to preserve the original plan for the first argument.
  if (context.GetSubplan(operand).empty()) {
    // Indicates another extension modified the step. Nothing to do here.
    return absl::OkStatus();
  }
  CEL_ASSIGN_OR_RETURN(auto operand_subplan, context.ExtractSubplan(operand));
  absl::c_move(operand_subplan, std::back_inserter(path));

  bool enable_wrapper_type_null_unboxing =
      context.options().enable_empty_wrapper_null_unboxing;
  path.push_back(std::make_unique<OptimizedSelectStep>(
      node.id(), std::move(attribute), std::move(instructions),
      std::move(qualifiers), presence_test, enable_wrapper_type_null_unboxing,
      options_));

  return context.ReplaceSubplan(node, std::move(path));
}

}  // namespace

absl::Status SelectOptimizationAstUpdater::UpdateAst(PlannerContext& context,
                                                     AstImpl& ast) const {
  RewriterImpl rewriter(ast, context);
  ast_internal::AstRewrite(&ast.root_expr(), &ast.source_info(), &rewriter);
  return rewriter.GetProgressStatus();
}

google::api::expr::runtime::ProgramOptimizerFactory
CreateSelectOptimizationProgramOptimizer(
    const SelectOptimizationOptions& options) {
  return [=](PlannerContext& context, const cel::ast_internal::AstImpl& ast) {
    return std::make_unique<SelectOptimizer>(options);
  };
}

}  // namespace cel::extensions
