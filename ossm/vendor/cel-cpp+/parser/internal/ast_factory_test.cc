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

#include "parser/internal/ast_factory.h"

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "common/constant.h"
#include "common/expr.h"
#include "internal/testing.h"
#include "parser/internal/ast_factory_interface.h"
#include "parser/macro.h"
#include "parser/macro_expr_factory.h"
#include "parser/macro_registry.h"

namespace cel::parser_internal {
namespace {

using ::absl_testing::IsOk;

using ::absl_testing::StatusIs;

TEST(AstFactoryInterfaceTest, AstFactoryUnspecified) {
  AstFactory factory;
  cel::Expr expr = factory.NewUnspecified(1);
  EXPECT_EQ(factory.GetId(expr), 1);
  EXPECT_FALSE(factory.IsEmpty(expr));
  EXPECT_FALSE(factory.IsConst(expr));
  EXPECT_FALSE(factory.IsIdent(expr));
  EXPECT_FALSE(factory.IsSelect(expr));

  cel::Expr empty_expr = factory.NewUnspecified(0);
  EXPECT_TRUE(factory.IsEmpty(empty_expr));
}

TEST(AstFactoryInterfaceTest, AstFactoryConstNodes) {
  AstFactory factory;

  cel::Expr null_expr = factory.NewNullConst(10);
  EXPECT_EQ(factory.GetId(null_expr), 10);
  EXPECT_TRUE(factory.IsConst(null_expr));
  ASSERT_TRUE(null_expr.has_const_expr());
  EXPECT_TRUE(null_expr.const_expr().has_null_value());

  cel::Expr bool_expr = factory.NewBoolConst(11, true);
  EXPECT_EQ(factory.GetId(bool_expr), 11);
  EXPECT_TRUE(factory.IsConst(bool_expr));
  ASSERT_TRUE(bool_expr.has_const_expr());
  EXPECT_TRUE(bool_expr.const_expr().bool_value());

  cel::Expr int_expr = factory.NewIntConst(12, -42);
  EXPECT_EQ(factory.GetId(int_expr), 12);
  EXPECT_TRUE(factory.IsConst(int_expr));
  ASSERT_TRUE(int_expr.has_const_expr());
  EXPECT_EQ(int_expr.const_expr().int_value(), -42);

  cel::Expr uint_expr = factory.NewUintConst(13, 100u);
  EXPECT_EQ(factory.GetId(uint_expr), 13);
  EXPECT_TRUE(factory.IsConst(uint_expr));
  ASSERT_TRUE(uint_expr.has_const_expr());
  EXPECT_EQ(uint_expr.const_expr().uint_value(), 100u);

  cel::Expr double_expr = factory.NewDoubleConst(14, 3.14159);
  EXPECT_EQ(factory.GetId(double_expr), 14);
  EXPECT_TRUE(factory.IsConst(double_expr));
  ASSERT_TRUE(double_expr.has_const_expr());
  EXPECT_DOUBLE_EQ(double_expr.const_expr().double_value(), 3.14159);

  cel::Expr bytes_expr = factory.NewBytesConst(15, "bytes_val");
  EXPECT_EQ(factory.GetId(bytes_expr), 15);
  EXPECT_TRUE(factory.IsConst(bytes_expr));
  ASSERT_TRUE(bytes_expr.has_const_expr());
  EXPECT_EQ(bytes_expr.const_expr().bytes_value(), "bytes_val");

  cel::Expr string_expr = factory.NewStringConst(16, "string_val");
  EXPECT_EQ(factory.GetId(string_expr), 16);
  EXPECT_TRUE(factory.IsConst(string_expr));
  ASSERT_TRUE(string_expr.has_const_expr());
  EXPECT_EQ(string_expr.const_expr().string_value(), "string_val");
}

TEST(AstFactoryInterfaceTest, AstFactoryIdentAndSelect) {
  AstFactory factory;

  cel::Expr ident_expr = factory.NewIdent(20, "foo");
  EXPECT_EQ(factory.GetId(ident_expr), 20);
  EXPECT_TRUE(factory.IsIdent(ident_expr));
  EXPECT_EQ(factory.GetIdentName(ident_expr), "foo");

  cel::Expr select_expr =
      factory.NewSelect(21, factory.NewIdent(20, "foo"), "bar");
  EXPECT_EQ(factory.GetId(select_expr), 21);
  EXPECT_TRUE(factory.IsSelect(select_expr));
  EXPECT_FALSE(factory.IsPresenceTest(select_expr));
  EXPECT_EQ(factory.GetSelectField(select_expr), "bar");
  ASSERT_NE(factory.GetSelectOperand(select_expr), nullptr);
  EXPECT_EQ(factory.GetIdentName(*factory.GetSelectOperand(select_expr)),
            "foo");

  cel::Expr presence_expr =
      factory.NewPresenceTest(22, factory.NewIdent(20, "foo"), "bar");
  EXPECT_EQ(factory.GetId(presence_expr), 22);
  EXPECT_TRUE(factory.IsSelect(presence_expr));
  EXPECT_TRUE(factory.IsPresenceTest(presence_expr));
  EXPECT_EQ(factory.GetSelectField(presence_expr), "bar");
}

TEST(AstFactoryInterfaceTest, AstFactoryCalls) {
  AstFactory factory;

  std::vector<cel::Expr> call_args;
  call_args.push_back(factory.NewIntConst(30, 1));
  call_args.push_back(factory.NewIntConst(31, 2));
  cel::Expr call_expr = factory.NewCall(32, "_+_", std::move(call_args));
  EXPECT_EQ(factory.GetId(call_expr), 32);
  ASSERT_TRUE(call_expr.has_call_expr());
  EXPECT_EQ(call_expr.call_expr().function(), "_+_");
  EXPECT_FALSE(call_expr.call_expr().has_target());
  EXPECT_EQ(call_expr.call_expr().args().size(), 2);

  std::vector<cel::Expr> member_args;
  member_args.push_back(factory.NewStringConst(33, "suffix"));
  cel::Expr member_call_expr = factory.NewMemberCall(
      34, "endsWith", factory.NewIdent(35, "str_var"), std::move(member_args));
  EXPECT_EQ(factory.GetId(member_call_expr), 34);
  ASSERT_TRUE(member_call_expr.has_call_expr());
  EXPECT_EQ(member_call_expr.call_expr().function(), "endsWith");
  EXPECT_TRUE(member_call_expr.call_expr().has_target());
  EXPECT_EQ(member_call_expr.call_expr().target().ident_expr().name(),
            "str_var");
  EXPECT_EQ(member_call_expr.call_expr().args().size(), 1);
}

TEST(AstFactoryInterfaceTest, AstFactoryList) {
  AstFactory factory;

  cel::Expr list_expr = factory.NewListBuilder(42)
                            .Add(factory.NewIntConst(40, 1), false)
                            .Add(factory.NewIntConst(41, 2), true)
                            .Build();
  EXPECT_EQ(factory.GetId(list_expr), 42);
  ASSERT_TRUE(list_expr.has_list_expr());
  ASSERT_EQ(list_expr.list_expr().elements().size(), 2);
  EXPECT_FALSE(list_expr.list_expr().elements()[0].optional());
  EXPECT_EQ(list_expr.list_expr().elements()[0].expr().const_expr().int_value(),
            1);
  EXPECT_TRUE(list_expr.list_expr().elements()[1].optional());
  EXPECT_EQ(list_expr.list_expr().elements()[1].expr().const_expr().int_value(),
            2);
}

TEST(AstFactoryInterfaceTest, AstFactoryStruct) {
  AstFactory factory;

  cel::Expr struct_expr =
      factory.NewStructBuilder(54, "MyMessage")
          .Add(50, "field1", factory.NewIntConst(51, 100), false)
          .Add(52, "field2", factory.NewIntConst(53, 200), true)
          .Build();
  EXPECT_EQ(factory.GetId(struct_expr), 54);
  ASSERT_TRUE(struct_expr.has_struct_expr());
  EXPECT_EQ(struct_expr.struct_expr().name(), "MyMessage");
  ASSERT_EQ(struct_expr.struct_expr().fields().size(), 2);
  EXPECT_EQ(struct_expr.struct_expr().fields()[0].id(), 50);
  EXPECT_EQ(struct_expr.struct_expr().fields()[0].name(), "field1");
  EXPECT_FALSE(struct_expr.struct_expr().fields()[0].optional());
  EXPECT_EQ(struct_expr.struct_expr().fields()[1].id(), 52);
  EXPECT_EQ(struct_expr.struct_expr().fields()[1].name(), "field2");
  EXPECT_TRUE(struct_expr.struct_expr().fields()[1].optional());
}

TEST(AstFactoryInterfaceTest, AstFactoryMap) {
  AstFactory factory;

  cel::Expr map_expr = factory.NewMapBuilder(66)
                           .Add(60, factory.NewStringConst(61, "key1"),
                                factory.NewIntConst(62, 10), false)
                           .Add(63, factory.NewStringConst(64, "key2"),
                                factory.NewIntConst(65, 20), true)
                           .Build();
  EXPECT_EQ(factory.GetId(map_expr), 66);
  ASSERT_TRUE(map_expr.has_map_expr());
  ASSERT_EQ(map_expr.map_expr().entries().size(), 2);
  EXPECT_EQ(map_expr.map_expr().entries()[0].id(), 60);
  EXPECT_EQ(map_expr.map_expr().entries()[0].key().const_expr().string_value(),
            "key1");
  EXPECT_EQ(map_expr.map_expr().entries()[0].value().const_expr().int_value(),
            10);
  EXPECT_FALSE(map_expr.map_expr().entries()[0].optional());
  EXPECT_EQ(map_expr.map_expr().entries()[1].id(), 63);
  EXPECT_TRUE(map_expr.map_expr().entries()[1].optional());
}

TEST(AstFactoryInterfaceTest, CopyAndReplace) {
  AstFactory factory;

  // x + 1
  std::vector<cel::Expr> args;
  args.push_back(factory.NewIdent(1, "x"));
  args.push_back(factory.NewIntConst(2, 1));
  cel::Expr expr = factory.NewCall(3, "_+_", std::move(args));

  // Transform: x -> y, 1 -> 2
  ASSERT_OK_AND_ASSIGN(
      cel::Expr transformed,
      factory.CopyAndReplace(
          expr, [&](const cel::Expr& e) -> std::optional<cel::Expr> {
            if (e.has_ident_expr() && e.ident_expr().name() == "x") {
              return factory.NewIdent(e.id(), "y");
            }
            if (e.has_const_expr() && e.const_expr().has_int_value() &&
                e.const_expr().int_value() == 1) {
              return factory.NewIntConst(e.id(), 2);
            }
            return std::nullopt;
          }));

  // Expected: y + 2
  std::vector<cel::Expr> expected_args;
  expected_args.push_back(factory.NewIdent(1, "y"));
  expected_args.push_back(factory.NewIntConst(2, 2));
  cel::Expr expected = factory.NewCall(3, "_+_", std::move(expected_args));

  EXPECT_EQ(transformed, expected);
}

TEST(AstFactoryInterfaceTest, CopyAndReplaceDeep) {
  AstFactory factory;

  auto replacer = [&](const cel::Expr& e) -> std::optional<cel::Expr> {
    if (e.has_const_expr() && e.const_expr().has_double_value()) {
      return factory.NewIntConst(
          e.id(), static_cast<int64_t>(e.const_expr().double_value()));
    }
    return std::nullopt;
  };

  cel::Expr expr = factory.NewCall(
      1, "func",
      std::vector<cel::Expr>{
          factory.NewListBuilder(2)
              .Add(factory.NewUnspecified(3))
              .Add(factory.NewNullConst(4))
              .Add(factory.NewBoolConst(5, true))
              .Add(factory.NewIntConst(6, 42))
              .Build(),
          factory.NewMapBuilder(7)
              .Add(991, factory.NewStringConst(8, "k1"),
                   factory.NewUintConst(9, 100u))
              .Add(992, factory.NewBytesConst(10, "b1"),
                   factory.NewDoubleConst(11, 3.14159))
              .Build(),
          factory.NewStructBuilder(12, "S")
              .Add(32, "f1", factory.NewIdent(13, "x"))
              .Add(
                  33, "f2",
                  factory.NewSelect(14, factory.NewIdent(15, "y"), "sel_field"))
              .Add(34, "f3",
                   factory.NewPresenceTest(16, factory.NewIdent(17, "z"),
                                           "pres_field"))
              .Build(),
          factory.NewMemberCall(
              18, "mem_func", factory.NewIdent(19, "target"),
              std::vector<cel::Expr>{[&]() {
                cel::Expr comp_expr;
                comp_expr.set_id(20);
                auto& comp = comp_expr.mutable_comprehension_expr();
                comp.set_iter_var("i");
                comp.set_iter_var2("i2");
                comp.set_accu_var("a");
                comp.set_accu_init(factory.NewDoubleConst(21, 2.71828));
                comp.set_iter_range(factory.NewIdent(22, "range"));
                comp.set_loop_condition(factory.NewBoolConst(23, true));
                comp.set_loop_step(factory.NewCall(
                    24, "step_func",
                    std::vector<cel::Expr>{factory.NewIdent(25, "accu")}));
                comp.set_result(factory.NewIdent(26, "result"));
                return comp_expr;
              }()})});

  ASSERT_OK_AND_ASSIGN(cel::Expr transformed_expr,
                       factory.CopyAndReplace(expr, replacer));

  cel::Expr expected_transformed_expr = factory.NewCall(
      1, "func",
      std::vector<cel::Expr>{
          factory.NewListBuilder(2)
              .Add(factory.NewUnspecified(3))
              .Add(factory.NewNullConst(4))
              .Add(factory.NewBoolConst(5, true))
              .Add(factory.NewIntConst(6, 42))
              .Build(),
          factory.NewMapBuilder(7)
              .Add(991, factory.NewStringConst(8, "k1"),
                   factory.NewUintConst(9, 100u))
              .Add(992, factory.NewBytesConst(10, "b1"),
                   factory.NewIntConst(11, 3))  // 3.14159 -> 3
              .Build(),
          factory.NewStructBuilder(12, "S")
              .Add(32, "f1", factory.NewIdent(13, "x"))
              .Add(
                  33, "f2",
                  factory.NewSelect(14, factory.NewIdent(15, "y"), "sel_field"))
              .Add(34, "f3",
                   factory.NewPresenceTest(16, factory.NewIdent(17, "z"),
                                           "pres_field"))
              .Build(),
          factory.NewMemberCall(
              18, "mem_func", factory.NewIdent(19, "target"),
              std::vector<cel::Expr>{[&]() {
                cel::Expr comp_expr;
                comp_expr.set_id(20);
                auto& comp = comp_expr.mutable_comprehension_expr();
                comp.set_iter_var("i");
                comp.set_iter_var2("i2");
                comp.set_accu_var("a");
                comp.set_accu_init(factory.NewIntConst(21, 2));  // 2.71828 -> 2
                comp.set_iter_range(factory.NewIdent(22, "range"));
                comp.set_loop_condition(factory.NewBoolConst(23, true));
                comp.set_loop_step(factory.NewCall(
                    24, "step_func",
                    std::vector<cel::Expr>{factory.NewIdent(25, "accu")}));
                comp.set_result(factory.NewIdent(26, "result"));
                return comp_expr;
              }()})});

  EXPECT_EQ(transformed_expr, expected_transformed_expr);
}

TEST(AstFactoryInterfaceTest, CopyAndReplacePrune) {
  AstFactory factory;

  // (x + 1) + 2
  std::vector<cel::Expr> inner_args;
  inner_args.push_back(factory.NewIdent(1, "x"));
  inner_args.push_back(factory.NewIntConst(2, 1));
  cel::Expr inner_expr = factory.NewCall(3, "_+_", std::move(inner_args));

  std::vector<cel::Expr> args;
  args.push_back(std::move(inner_expr));
  args.push_back(factory.NewIntConst(4, 2));
  cel::Expr expr = factory.NewCall(5, "_+_", std::move(args));

  // Replace the inner call (id 3) with a single ident "y" (id 9), pruning the
  // subtree.
  ASSERT_OK_AND_ASSIGN(
      cel::Expr transformed,
      factory.CopyAndReplace(
          expr, [&](const cel::Expr& e) -> std::optional<cel::Expr> {
            if (e.id() == 3) {
              return factory.NewIdent(9, "y");
            }
            return std::nullopt;
          }));

  // Expected: y + 2
  std::vector<cel::Expr> expected_args;
  expected_args.push_back(factory.NewIdent(9, "y"));
  expected_args.push_back(factory.NewIntConst(4, 2));
  cel::Expr expected = factory.NewCall(5, "_+_", std::move(expected_args));

  EXPECT_EQ(transformed, expected);
}

TEST(AstFactoryInterfaceTest, CopyAndReplaceMaxRecursionDepth) {
  AstFactory factory;

  cel::Expr expr = factory.NewIdent(1, "x");
  for (int i = 2; i <= 10; ++i) {
    std::vector<cel::Expr> args;
    args.push_back(std::move(expr));
    args.push_back(factory.NewIntConst(i, 1));
    expr = factory.NewCall(i, "_+_", std::move(args));
  }

  EXPECT_THAT(factory.CopyAndReplace(
                  expr,
                  [](const cel::Expr&) -> std::optional<cel::Expr> {
                    return std::nullopt;
                  },
                  /*max_recursion_depth=*/3),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

class TestMacroExprExpanderSupport
    : public MacroExprExpanderSupport<cel::Expr> {
 public:
  int64_t NextId() override { return 42; }
  int64_t CopyId(int64_t id) override { return id; }
  cel::Expr ReportError(absl::string_view) override { return cel::Expr(); }
  cel::Expr ReportErrorAt(const cel::Expr&, absl::string_view) override {
    return cel::Expr();
  }
};

TEST(AstFactoryInterfaceTest, MacroExprExpander) {
  MacroRegistry macro_registry;
  AstFactory factory(&macro_registry);
  ASSERT_OK_AND_ASSIGN(
      auto foo_macro,
      Macro::Global("foo", 1,
                    [](MacroExprFactory& macro_factory,
                       absl::Span<Expr> args) -> std::optional<Expr> {
                      return macro_factory.NewCall("my_macro", std::move(args));
                    }));

  ASSERT_THAT(macro_registry.RegisterMacro(foo_macro), IsOk());

  auto expander1 = factory.NewMacroExprExpander("foo", 1, false);
  ASSERT_TRUE(expander1.has_value());

  std::vector<Expr> expand_args;
  expand_args.push_back(factory.NewIdent(1, "x"));

  TestMacroExprExpanderSupport support;
  auto result =
      expander1->Expand(std::nullopt, absl::MakeSpan(expand_args), support);
  ASSERT_TRUE(result.has_value());

  std::vector<Expr> expected_args;
  expected_args.push_back(factory.NewIdent(1, "x"));
  Expr expected = factory.NewCall(42, "my_macro", std::move(expected_args));

  EXPECT_EQ(*result, expected);

  auto expander2 = factory.NewMacroExprExpander("bar", 1, false);
  EXPECT_FALSE(expander2.has_value());
}

}  // namespace
}  // namespace cel::parser_internal
