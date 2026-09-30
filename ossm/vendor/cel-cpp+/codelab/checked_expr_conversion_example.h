// Copyright 2026 Google LLC
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

#ifndef THIRD_PARTY_CEL_CPP_CODELAB_CHECKED_EXPR_CONVERSION_EXAMPLE_H_
#define THIRD_PARTY_CEL_CPP_CODELAB_CHECKED_EXPR_CONVERSION_EXAMPLE_H_

#include <memory>

#include "cel/expr/checked.pb.h"
#include "absl/status/statusor.h"
#include "common/ast.h"
#include "common/ast_proto.h"
#include "internal/status_macros.h"

namespace cel_codelab {

// Examples demonstrating how to convert between protobuf-based AST
// representations (cel::expr::CheckedExpr) and modern runtime AST
// representations (cel::Ast).
//
// When evaluating expressions with modern `cel::Runtime`, compilation via
// `cel::Compiler::Compile` returns a `cel::ValidationResult` holding a
// `cel::Ast` that can be passed directly to `runtime->CreateProgram(...)`.
//
// However, when working with external services or storage layers that persist
// or transmit serialized protobuf ASTs (`cel::expr::CheckedExpr`),
// conversion functions in `common/ast_proto.h` can be used
// to move between `cel::Ast` and `cel::expr::CheckedExpr`.

// Example: Convert a runtime `cel::Ast` to a `cel::expr::CheckedExpr`
// proto.
inline absl::StatusOr<cel::expr::CheckedExpr> ConvertAstToCheckedExpr(
    const cel::Ast& ast) {
  cel::expr::CheckedExpr checked_expr;
  CEL_RETURN_IF_ERROR(cel::AstToCheckedExpr(ast, &checked_expr));
  return checked_expr;
}

// Example: Convert a `cel::expr::CheckedExpr` proto to a runtime
// `cel::Ast`.
inline absl::StatusOr<std::unique_ptr<cel::Ast>> ConvertCheckedExprToAst(
    const cel::expr::CheckedExpr& checked_expr) {
  return cel::CreateAstFromCheckedExpr(checked_expr);
}

}  // namespace cel_codelab

#endif  // THIRD_PARTY_CEL_CPP_CODELAB_CHECKED_EXPR_CONVERSION_EXAMPLE_H_
