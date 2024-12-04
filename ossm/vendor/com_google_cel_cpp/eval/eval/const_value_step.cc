#include "eval/eval/const_value_step.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/status/statusor.h"
#include "base/ast_internal/expr.h"
#include "base/handle.h"
#include "base/value.h"
#include "base/value_factory.h"
#include "eval/eval/compiler_constant_step.h"
#include "eval/eval/evaluator_core.h"
#include "internal/status_macros.h"
#include "runtime/internal/convert_constant.h"

namespace google::api::expr::runtime {

using ::cel::ast_internal::Constant;
using ::cel::runtime_internal::ConvertConstant;

absl::StatusOr<std::unique_ptr<ExpressionStep>> CreateConstValueStep(
    cel::Handle<cel::Value> value, int64_t expr_id, bool comes_from_ast) {
  return std::make_unique<CompilerConstantStep>(std::move(value), expr_id,
                                                comes_from_ast);
}

absl::StatusOr<std::unique_ptr<ExpressionStep>> CreateConstValueStep(
    const Constant& value, int64_t expr_id, cel::ValueFactory& value_factory,
    bool comes_from_ast) {
  CEL_ASSIGN_OR_RETURN(cel::Handle<cel::Value> converted_value,
                       ConvertConstant(value, value_factory));

  return std::make_unique<CompilerConstantStep>(std::move(converted_value),
                                                expr_id, comes_from_ast);
}

}  // namespace google::api::expr::runtime
