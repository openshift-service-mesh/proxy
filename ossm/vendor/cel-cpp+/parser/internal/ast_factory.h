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

#ifndef THIRD_PARTY_CEL_CPP_PARSER_INTERNAL_AST_FACTORY_H_
#define THIRD_PARTY_CEL_CPP_PARSER_INTERNAL_AST_FACTORY_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/functional/function_ref.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "common/expr.h"
#include "common/expr_factory.h"
#include "parser/internal/ast_factory_interface.h"
#include "parser/macro.h"
#include "parser/macro_expr_factory.h"
#include "parser/macro_registry.h"

namespace cel::parser_internal {

// Explicit specialization of `AstFactoryInterface` for `cel::Expr` AST nodes.

template <>
class ListNodeBuilder<cel::Expr> {
 public:
  explicit ListNodeBuilder(int64_t id);

  ListNodeBuilder& Add(cel::Expr element, bool optional = false);

  cel::Expr Build();

 private:
  cel::Expr expr_;
};

template <>
class MapNodeBuilder<cel::Expr> {
 public:
  explicit MapNodeBuilder(int64_t id);

  MapNodeBuilder& Add(int64_t id, cel::Expr key, cel::Expr value,
                      bool optional = false);

  cel::Expr Build();

 private:
  cel::Expr expr_;
};

template <>
class StructNodeBuilder<cel::Expr> {
 public:
  explicit StructNodeBuilder(int64_t id, std::string name);

  StructNodeBuilder& Add(int64_t id, std::string name, cel::Expr value,
                         bool optional = false);

  cel::Expr Build();

 private:
  cel::Expr expr_;
};

template <>
class AstFactoryInterface<cel::Expr>;

template <>
class MacroExprExpanderSupport<cel::Expr> : public cel::MacroExprFactory {};

template <>
class MacroExprExpander<cel::Expr> {
 public:
  explicit MacroExprExpander(cel::Macro macro) : macro_(std::move(macro)) {}

  std::optional<cel::Expr> Expand(
      std::optional<std::reference_wrapper<cel::Expr>> target,
      absl::Span<cel::Expr> args,
      MacroExprExpanderSupport<cel::Expr>& support) {
    return macro_.Expand(support, target, args);
  }

 private:
  cel::Macro macro_;
};

template <>
class AstFactoryInterface<cel::Expr> : public cel::ExprFactory {
 public:
  explicit AstFactoryInterface(
      const cel::MacroRegistry* absl_nullable macro_registry = nullptr)
      : macro_registry_(macro_registry) {}

  AstFactoryInterface(const AstFactoryInterface&) = delete;
  AstFactoryInterface(AstFactoryInterface&&) = delete;
  AstFactoryInterface& operator=(const AstFactoryInterface&) = delete;
  AstFactoryInterface& operator=(AstFactoryInterface&&) = delete;

  ~AstFactoryInterface() override = default;

  // Node inspection and encapsulation API
  int64_t GetId(const cel::Expr& expr) const;

  bool IsEmpty(const cel::Expr& expr) const;

  bool IsConst(const cel::Expr& expr) const;

  bool IsIdent(const cel::Expr& expr) const;

  absl::string_view GetIdentName(const cel::Expr& expr) const;

  bool IsSelect(const cel::Expr& expr) const;

  bool IsPresenceTest(const cel::Expr& expr) const;

  const cel::Expr* GetSelectOperand(const cel::Expr& expr) const;

  absl::string_view GetSelectField(const cel::Expr& expr) const;

  absl::StatusOr<cel::Expr> CopyAndReplace(
      const cel::Expr& expr,
      absl::FunctionRef<std::optional<cel::Expr>(const cel::Expr&)> replacer,
      int max_recursion_depth = 1000) const;

  // Node creation API
  using cel::ExprFactory::NewBoolConst;
  using cel::ExprFactory::NewBytesConst;
  using cel::ExprFactory::NewCall;
  using cel::ExprFactory::NewDoubleConst;
  using cel::ExprFactory::NewIdent;
  using cel::ExprFactory::NewIntConst;
  using cel::ExprFactory::NewMemberCall;
  using cel::ExprFactory::NewNullConst;
  using cel::ExprFactory::NewPresenceTest;
  using cel::ExprFactory::NewSelect;
  using cel::ExprFactory::NewStringConst;
  using cel::ExprFactory::NewUintConst;
  using cel::ExprFactory::NewUnspecified;

  ListNodeBuilder<cel::Expr> NewListBuilder(int64_t id);

  StructNodeBuilder<cel::Expr> NewStructBuilder(int64_t id, std::string name);

  MapNodeBuilder<cel::Expr> NewMapBuilder(int64_t id);

  std::optional<MacroExprExpander<cel::Expr>> NewMacroExprExpander(
      std::string_view name, size_t arg_count, bool receiver_style);

 private:
  const cel::MacroRegistry* absl_nullable macro_registry_ = nullptr;
};

using AstFactory = AstFactoryInterface<cel::Expr>;

}  // namespace cel::parser_internal

#endif  // THIRD_PARTY_CEL_CPP_PARSER_INTERNAL_AST_FACTORY_H_
