// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef THIRD_PARTY_CEL_CPP_EVAL_EVAL_CEL_EXPRESSION_FLAT_IMPL_H_
#define THIRD_PARTY_CEL_CPP_EVAL_EVAL_CEL_EXPRESSION_FLAT_IMPL_H_

#include <memory>
#include <utility>

#include "eval/eval/evaluator_core.h"
#include "eval/public/cel_expression.h"
#include "extensions/protobuf/memory_manager.h"

namespace google::api::expr::runtime {

// Wrapper for FlatExpressionEvaluationState used to implement CelExpression.
class CelExpressionFlatEvaluationState : public CelEvaluationState {
 public:
  CelExpressionFlatEvaluationState(google::protobuf::Arena* arena,
                                   const FlatExpression& expr);

  google::protobuf::Arena* arena() { return arena_; }
  FlatExpressionEvaluatorState& state() { return state_; }

 private:
  google::protobuf::Arena* arena_;
  FlatExpressionEvaluatorState state_;
};

// Implementation of the CelExpression that evaluates a flattened representation
// of the AST.
//
// This class adapts FlatExpression to implement the CelExpression interface.
class CelExpressionFlatImpl : public CelExpression {
 public:
  explicit CelExpressionFlatImpl(FlatExpression flat_expression)
      : flat_expression_(std::move(flat_expression)) {}

  // Move-only
  CelExpressionFlatImpl(const CelExpressionFlatImpl&) = delete;
  CelExpressionFlatImpl& operator=(const CelExpressionFlatImpl&) = delete;
  CelExpressionFlatImpl(CelExpressionFlatImpl&&) = default;
  CelExpressionFlatImpl& operator=(CelExpressionFlatImpl&&) = delete;

  // Implement CelExpression.
  std::unique_ptr<CelEvaluationState> InitializeState(
      google::protobuf::Arena* arena) const override;

  absl::StatusOr<CelValue> Evaluate(const BaseActivation& activation,
                                    google::protobuf::Arena* arena) const override {
    return Evaluate(activation, InitializeState(arena).get());
  }

  absl::StatusOr<CelValue> Evaluate(const BaseActivation& activation,
                                    CelEvaluationState* state) const override;
  absl::StatusOr<CelValue> Trace(
      const BaseActivation& activation, google::protobuf::Arena* arena,
      CelEvaluationListener callback) const override {
    return Trace(activation, InitializeState(arena).get(), callback);
  }

  absl::StatusOr<CelValue> Trace(const BaseActivation& activation,
                                 CelEvaluationState* state,
                                 CelEvaluationListener callback) const override;

  // Exposed for inspection in tests.
  const FlatExpression& flat_expression() const { return flat_expression_; }

 private:
  FlatExpression flat_expression_;
};

}  // namespace google::api::expr::runtime

#endif  // THIRD_PARTY_CEL_CPP_EVAL_EVAL_CEL_EXPRESSION_FLAT_IMPL_H_
