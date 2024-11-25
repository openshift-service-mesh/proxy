// Copyright 2019 Google LLC
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

#include "eval/compiler/constant_folding.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/variant.h"
#include "base/ast_internal/ast_impl.h"
#include "base/ast_internal/expr.h"
#include "base/builtins.h"
#include "base/handle.h"
#include "base/kind.h"
#include "base/type_provider.h"
#include "base/value.h"
#include "base/value_factory.h"
#include "base/values/unknown_value.h"
#include "eval/compiler/flat_expr_builder_extensions.h"
#include "eval/compiler/resolver.h"
#include "eval/eval/const_value_step.h"
#include "eval/eval/evaluator_core.h"
#include "internal/status_macros.h"
#include "runtime/activation.h"
#include "runtime/internal/convert_constant.h"

namespace cel::runtime_internal {

namespace {

using ::cel::ast_internal::AstImpl;
using ::cel::ast_internal::Call;
using ::cel::ast_internal::Comprehension;
using ::cel::ast_internal::Constant;
using ::cel::ast_internal::CreateList;
using ::cel::ast_internal::CreateStruct;
using ::cel::ast_internal::Expr;
using ::cel::ast_internal::Ident;
using ::cel::ast_internal::Select;
using ::cel::builtin::kAnd;
using ::cel::builtin::kOr;
using ::cel::builtin::kTernary;
using ::cel::runtime_internal::ConvertConstant;

using ::google::api::expr::runtime::EvaluationListener;
using ::google::api::expr::runtime::ExecutionFrame;
using ::google::api::expr::runtime::ExecutionPath;
using ::google::api::expr::runtime::ExecutionPathView;
using ::google::api::expr::runtime::FlatExpressionEvaluatorState;
using ::google::api::expr::runtime::PlannerContext;
using ::google::api::expr::runtime::ProgramOptimizer;
using ::google::api::expr::runtime::ProgramOptimizerFactory;
using ::google::api::expr::runtime::Resolver;

class ConstantFoldingExtension : public ProgramOptimizer {
 public:
  ConstantFoldingExtension(MemoryManagerRef memory_manager,
                           const TypeProvider& type_provider)
      : memory_manager_(memory_manager),
        state_(kDefaultStackLimit, kComprehensionSlotCount, type_provider,
               memory_manager_) {}

  absl::Status OnPreVisit(google::api::expr::runtime::PlannerContext& context,
                          const Expr& node) override;
  absl::Status OnPostVisit(google::api::expr::runtime::PlannerContext& context,
                           const Expr& node) override;

 private:
  enum class IsConst {
    kConditional,
    kNonConst,
  };
  // Most constant folding evaluations are simple
  // binary operators.
  static constexpr size_t kDefaultStackLimit = 4;

  // Comprehensions are not evaluated -- the current implementation can't detect
  // if the comprehension variables are only used in a const way.
  static constexpr size_t kComprehensionSlotCount = 0;

  MemoryManagerRef memory_manager_;
  Activation empty_;
  FlatExpressionEvaluatorState state_;

  std::vector<IsConst> is_const_;
};

absl::Status ConstantFoldingExtension::OnPreVisit(PlannerContext& context,
                                                  const Expr& node) {
  struct IsConstVisitor {
    IsConst operator()(const Constant&) { return IsConst::kConditional; }
    IsConst operator()(const Ident&) { return IsConst::kNonConst; }
    IsConst operator()(const Comprehension&) {
      // Not yet supported, need to identify whether range and
      // iter vars are compatible with const folding.
      return IsConst::kNonConst;
    }
    IsConst operator()(const CreateStruct& create_struct) {
      // Not yet supported but should be possible in the future.
      // Empty maps are rare and not currently supported as they may eventually
      // have similar issues to empty list when used within comprehensions or
      // macros.
      if (create_struct.entries().empty() ||
          !create_struct.message_name().empty()) {
        return IsConst::kNonConst;
      }
      return IsConst::kConditional;
    }
    IsConst operator()(const CreateList& create_list) {
      if (create_list.elements().empty()) {
        // TODO(uncreated-issue/35): Don't fold for empty list to allow comprehension
        // list append optimization.
        return IsConst::kNonConst;
      }
      return IsConst::kConditional;
    }

    IsConst operator()(const Select&) { return IsConst::kConditional; }

    IsConst operator()(absl::monostate) { return IsConst::kNonConst; }

    IsConst operator()(const Call& call) {
      // Short Circuiting operators not yet supported.
      if (call.function() == kAnd || call.function() == kOr ||
          call.function() == kTernary) {
        return IsConst::kNonConst;
      }

      int arg_len = call.args().size() + (call.has_target() ? 1 : 0);
      std::vector<cel::Kind> arg_matcher(arg_len, cel::Kind::kAny);
      // Check for any lazy overloads (activation dependant)
      if (!resolver
               .FindLazyOverloads(call.function(), call.has_target(),
                                  arg_matcher)
               .empty()) {
        return IsConst::kNonConst;
      }

      return IsConst::kConditional;
    }

    const Resolver& resolver;
  };

  IsConst is_const =
      absl::visit(IsConstVisitor{context.resolver()}, node.expr_kind());
  is_const_.push_back(is_const);

  return absl::OkStatus();
}

absl::Status ConstantFoldingExtension::OnPostVisit(PlannerContext& context,
                                                   const Expr& node) {
  if (is_const_.empty()) {
    return absl::InternalError("ConstantFoldingExtension called out of order.");
  }

  IsConst is_const = is_const_.back();
  is_const_.pop_back();

  if (is_const == IsConst::kNonConst) {
    // update parent
    if (!is_const_.empty()) {
      is_const_.back() = IsConst::kNonConst;
    }
    return absl::OkStatus();
  }
  ExecutionPathView subplan = context.GetSubplan(node);
  if (subplan.empty()) {
    // This subexpression is already optimized out or suppressed.
    return absl::OkStatus();
  }
  // copy string to managed handle if backed by the original program.
  Handle<Value> value;
  if (node.has_const_expr()) {
    CEL_ASSIGN_OR_RETURN(
        value, ConvertConstant(node.const_expr(), state_.value_factory()));
  } else {
    ExecutionFrame frame(subplan, empty_, context.options(), state_);
    state_.Reset();
    // Update stack size to accommodate sub expression.
    // This only results in a vector resize if the new maxsize is greater than
    // the current capacity.
    state_.value_stack().SetMaxSize(subplan.size());

    auto result = frame.Evaluate(EvaluationListener());
    // If this would be a runtime error, then don't adjust the program plan, but
    // rather allow the error to occur at runtime to preserve the evaluation
    // contract with non-constant folding use cases.
    if (!result.ok()) {
      return absl::OkStatus();
    }
    value = *result;
    if (value->Is<UnknownValue>()) {
      return absl::OkStatus();
    }
  }

  ExecutionPath new_plan;
  CEL_ASSIGN_OR_RETURN(new_plan.emplace_back(),
                       google::api::expr::runtime::CreateConstValueStep(
                           std::move(value), node.id(), false));

  return context.ReplaceSubplan(node, std::move(new_plan));
}

}  // namespace

ProgramOptimizerFactory CreateConstantFoldingOptimizer(
    MemoryManagerRef memory_manager) {
  return [memory_manager](PlannerContext& ctx, const AstImpl&)
             -> absl::StatusOr<std::unique_ptr<ProgramOptimizer>> {
    return std::make_unique<ConstantFoldingExtension>(
        memory_manager, ctx.value_factory().type_provider());
  };
}

}  // namespace cel::runtime_internal
