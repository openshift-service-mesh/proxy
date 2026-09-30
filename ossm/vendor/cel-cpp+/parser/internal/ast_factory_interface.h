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

#ifndef THIRD_PARTY_CEL_CPP_PARSER_INTERNAL_AST_FACTORY_INTERFACE_H_
#define THIRD_PARTY_CEL_CPP_PARSER_INTERNAL_AST_FACTORY_INTERFACE_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "absl/functional/function_ref.h"
#include "absl/status/statusor.h"
#include "absl/types/span.h"

namespace cel::parser_internal {

template <typename ExprNode>
class ListNodeBuilder {
 public:
  ListNodeBuilder& Add(ExprNode element, bool optional = false);
  ExprNode Build();
};

template <typename ExprNode>
class MapNodeBuilder {
 public:
  MapNodeBuilder& Add(int64_t id, ExprNode key, ExprNode value,
                      bool optional = false);
  ExprNode Build();
};

template <typename ExprNode>
class StructNodeBuilder {
 public:
  StructNodeBuilder& Add(int64_t id, std::string name, ExprNode value,
                         bool optional = false);
  ExprNode Build();
};

template <typename ExprNode>
class MacroExprExpanderSupport {};

template <typename ExprNode>
class MacroExprExpander {
 public:
  std::optional<ExprNode> Expand(
      std::optional<std::reference_wrapper<ExprNode>> target,
      absl::Span<ExprNode> args, MacroExprExpanderSupport<ExprNode>& support);
};

// Interface for decoupling parser logic from the underlying AST node
// data structures.
//
// By parameterizing the parser and factory on `ExprNode`, alternative AST node
// representations (such as `cel::Expr`) can be constructed without modifying
// parser rules.
//
// To implement AST construction using an alternative AST structure:
// 1. Define or specify your custom node type `MyNode`.
// 2. Implement a concrete factory specialization `AstFactoryInterface<MyNode>`
//    that provides inspection (`GetId`, `IsSelect`, etc.) and creation
//    (`NewCall`, `NewListBuilder`, etc.) operations for `MyNode`.
// 3. Instantiate the parser worker with your node type:
//    `PrattParserWorker<MyNode>`.
template <typename ExprNode>
class AstFactoryInterface {
 public:
  AstFactoryInterface() = default;
  AstFactoryInterface(const AstFactoryInterface&) = delete;
  AstFactoryInterface(AstFactoryInterface&&) = delete;
  AstFactoryInterface& operator=(const AstFactoryInterface&) = delete;
  AstFactoryInterface& operator=(AstFactoryInterface&&) = delete;

  int64_t GetId(const ExprNode& expr) const;
  bool IsEmpty(const ExprNode& expr) const;
  bool IsConst(const ExprNode& expr) const;
  bool IsIdent(const ExprNode& expr) const;
  std::string_view GetIdentName(const ExprNode& expr) const;
  bool IsSelect(const ExprNode& expr) const;
  bool IsPresenceTest(const ExprNode& expr) const;
  const ExprNode* GetSelectOperand(const ExprNode& expr) const;
  std::string_view GetSelectField(const ExprNode& expr) const;
  absl::StatusOr<ExprNode> CopyAndReplace(
      const ExprNode& expr,
      absl::FunctionRef<std::optional<ExprNode>(const ExprNode&)> replacer,
      int max_recursion_depth = 1000) const;

  ExprNode NewUnspecified(int64_t id);
  ExprNode NewNullConst(int64_t id);
  ExprNode NewBoolConst(int64_t id, bool value);
  ExprNode NewIntConst(int64_t id, int64_t value);
  ExprNode NewUintConst(int64_t id, uint64_t value);
  ExprNode NewDoubleConst(int64_t id, double value);
  ExprNode NewBytesConst(int64_t id, std::string value);
  ExprNode NewStringConst(int64_t id, std::string value);
  ExprNode NewIdent(int64_t id, std::string name);
  ExprNode NewSelect(int64_t id, ExprNode operand, std::string field);
  ExprNode NewPresenceTest(int64_t id, ExprNode operand, std::string field);
  ExprNode NewCall(int64_t id, std::string function,
                   std::vector<ExprNode> args);
  ExprNode NewMemberCall(int64_t id, std::string function, ExprNode target,
                         std::vector<ExprNode> args);
  ListNodeBuilder<ExprNode> NewListBuilder(int64_t id);
  MapNodeBuilder<ExprNode> NewMapBuilder(int64_t id);
  StructNodeBuilder<ExprNode> NewStructBuilder(int64_t id, std::string name);

  // Returns a macro expander for the given macro name, or null if there
  // is no registered macro with that name and argument count.
  std::optional<MacroExprExpander<ExprNode>> NewMacroExprExpander(
      std::string_view name, size_t arg_count, bool receiver_style);
};

}  // namespace cel::parser_internal

#endif  // THIRD_PARTY_CEL_CPP_PARSER_INTERNAL_AST_FACTORY_INTERFACE_H_
