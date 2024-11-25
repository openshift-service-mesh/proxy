#include "eval/eval/create_list_step.h"

#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "eval/eval/cel_expression_flat_impl.h"
#include "eval/eval/const_value_step.h"
#include "eval/eval/evaluator_core.h"
#include "eval/eval/ident_step.h"
#include "eval/internal/interop.h"
#include "eval/public/activation.h"
#include "eval/public/cel_attribute.h"
#include "eval/public/testing/matchers.h"
#include "eval/public/unknown_attribute_set.h"
#include "internal/status_macros.h"
#include "internal/testing.h"
#include "runtime/runtime_options.h"

namespace google::api::expr::runtime {

namespace {

using ::cel::TypeProvider;
using ::cel::ast_internal::Expr;
using testing::Eq;
using testing::Not;
using cel::internal::IsOk;

// Helper method. Creates simple pipeline containing Select step and runs it.
absl::StatusOr<CelValue> RunExpression(const std::vector<int64_t>& values,
                                       google::protobuf::Arena* arena,
                                       bool enable_unknowns) {
  ExecutionPath path;
  Expr dummy_expr;

  auto& create_list = dummy_expr.mutable_list_expr();
  for (auto value : values) {
    auto& expr0 = create_list.mutable_elements().emplace_back();
    expr0.mutable_const_expr().set_int64_value(value);
    CEL_ASSIGN_OR_RETURN(
        auto const_step,
        CreateConstValueStep(cel::interop_internal::CreateIntValue(value),
                             /*expr_id=*/-1));
    path.push_back(std::move(const_step));
  }

  CEL_ASSIGN_OR_RETURN(auto step,
                       CreateCreateListStep(create_list, dummy_expr.id()));
  path.push_back(std::move(step));
  cel::RuntimeOptions options;
  if (enable_unknowns) {
    options.unknown_processing = cel::UnknownProcessingOptions::kAttributeOnly;
  }
  CelExpressionFlatImpl cel_expr(

      FlatExpression(std::move(path),
                     /*comprehension_slot_count=*/0, TypeProvider::Builtin(),
                     options));
  Activation activation;

  return cel_expr.Evaluate(activation, arena);
}

// Helper method. Creates simple pipeline containing Select step and runs it.
absl::StatusOr<CelValue> RunExpressionWithCelValues(
    const std::vector<CelValue>& values, google::protobuf::Arena* arena,
    bool enable_unknowns) {
  ExecutionPath path;
  Expr dummy_expr;

  Activation activation;
  auto& create_list = dummy_expr.mutable_list_expr();
  int ind = 0;
  for (auto value : values) {
    std::string var_name = absl::StrCat("name_", ind++);
    auto& expr0 = create_list.mutable_elements().emplace_back();
    expr0.set_id(ind);
    expr0.mutable_ident_expr().set_name(var_name);

    CEL_ASSIGN_OR_RETURN(auto ident_step,
                         CreateIdentStep(expr0.ident_expr(), expr0.id()));
    path.push_back(std::move(ident_step));
    activation.InsertValue(var_name, value);
  }

  CEL_ASSIGN_OR_RETURN(auto step0,
                       CreateCreateListStep(create_list, dummy_expr.id()));
  path.push_back(std::move(step0));

  cel::RuntimeOptions options;
  if (enable_unknowns) {
    options.unknown_processing = cel::UnknownProcessingOptions::kAttributeOnly;
  }

  CelExpressionFlatImpl cel_expr(
      FlatExpression(std::move(path), /*comprehension_slot_count=*/0,
                     TypeProvider::Builtin(), options));

  return cel_expr.Evaluate(activation, arena);
}

class CreateListStepTest : public testing::TestWithParam<bool> {};

// Tests error when not enough list elements are on the stack during list
// creation.
TEST(CreateListStepTest, TestCreateListStackUnderflow) {
  ExecutionPath path;
  Expr dummy_expr;

  auto& create_list = dummy_expr.mutable_list_expr();
  auto& expr0 = create_list.mutable_elements().emplace_back();
  expr0.mutable_const_expr().set_int64_value(1);

  ASSERT_OK_AND_ASSIGN(auto step0,
                       CreateCreateListStep(create_list, dummy_expr.id()));
  path.push_back(std::move(step0));

  CelExpressionFlatImpl cel_expr(
      FlatExpression(std::move(path), /*comprehension_slot_count=*/0,
                     TypeProvider::Builtin(), cel::RuntimeOptions{}));
  Activation activation;

  google::protobuf::Arena arena;

  auto status = cel_expr.Evaluate(activation, &arena);
  ASSERT_THAT(status, Not(IsOk()));
}

TEST_P(CreateListStepTest, CreateListEmpty) {
  google::protobuf::Arena arena;
  ASSERT_OK_AND_ASSIGN(CelValue result, RunExpression({}, &arena, GetParam()));
  ASSERT_TRUE(result.IsList());
  EXPECT_THAT(result.ListOrDie()->size(), Eq(0));
}

TEST_P(CreateListStepTest, CreateListOne) {
  google::protobuf::Arena arena;
  ASSERT_OK_AND_ASSIGN(CelValue result,
                       RunExpression({100}, &arena, GetParam()));
  ASSERT_TRUE(result.IsList());
  const auto& list = *result.ListOrDie();
  ASSERT_THAT(list.size(), Eq(1));
  const CelValue& value = list.Get(&arena, 0);
  EXPECT_THAT(value, test::IsCelInt64(100));
}

TEST_P(CreateListStepTest, CreateListWithError) {
  google::protobuf::Arena arena;
  std::vector<CelValue> values;
  CelError error = absl::InvalidArgumentError("bad arg");
  values.push_back(CelValue::CreateError(&error));
  ASSERT_OK_AND_ASSIGN(CelValue result,
                       RunExpressionWithCelValues(values, &arena, GetParam()));

  ASSERT_TRUE(result.IsError());
  EXPECT_THAT(*result.ErrorOrDie(), Eq(absl::InvalidArgumentError("bad arg")));
}

TEST_P(CreateListStepTest, CreateListWithErrorAndUnknown) {
  google::protobuf::Arena arena;
  // list composition is: {unknown, error}
  std::vector<CelValue> values;
  Expr expr0;
  expr0.mutable_ident_expr().set_name("name0");
  CelAttribute attr0(expr0.ident_expr().name(), {});
  UnknownSet unknown_set0(UnknownAttributeSet({attr0}));
  values.push_back(CelValue::CreateUnknownSet(&unknown_set0));
  CelError error = absl::InvalidArgumentError("bad arg");
  values.push_back(CelValue::CreateError(&error));

  ASSERT_OK_AND_ASSIGN(CelValue result,
                       RunExpressionWithCelValues(values, &arena, GetParam()));

  // The bad arg should win.
  ASSERT_TRUE(result.IsError());
  EXPECT_THAT(*result.ErrorOrDie(), Eq(absl::InvalidArgumentError("bad arg")));
}

TEST_P(CreateListStepTest, CreateListHundred) {
  google::protobuf::Arena arena;
  std::vector<int64_t> values;
  for (size_t i = 0; i < 100; i++) {
    values.push_back(i);
  }
  ASSERT_OK_AND_ASSIGN(CelValue result,
                       RunExpression(values, &arena, GetParam()));
  ASSERT_TRUE(result.IsList());
  const auto& list = *result.ListOrDie();
  EXPECT_THAT(list.size(), Eq(static_cast<int>(values.size())));
  for (size_t i = 0; i < values.size(); i++) {
    EXPECT_THAT(list.Get(&arena, i), test::IsCelInt64(values[i]));
  }
}

TEST(CreateListStepTest, CreateListHundredAnd2Unknowns) {
  google::protobuf::Arena arena;
  std::vector<CelValue> values;

  Expr expr0;
  expr0.mutable_ident_expr().set_name("name0");
  CelAttribute attr0(expr0.ident_expr().name(), {});
  Expr expr1;
  expr1.mutable_ident_expr().set_name("name1");
  CelAttribute attr1(expr1.ident_expr().name(), {});
  UnknownSet unknown_set0(UnknownAttributeSet({attr0}));
  UnknownSet unknown_set1(UnknownAttributeSet({attr1}));
  for (size_t i = 0; i < 100; i++) {
    values.push_back(CelValue::CreateInt64(i));
  }
  values.push_back(CelValue::CreateUnknownSet(&unknown_set0));
  values.push_back(CelValue::CreateUnknownSet(&unknown_set1));

  ASSERT_OK_AND_ASSIGN(CelValue result,
                       RunExpressionWithCelValues(values, &arena, true));
  ASSERT_TRUE(result.IsUnknownSet());
  const UnknownSet* result_set = result.UnknownSetOrDie();
  EXPECT_THAT(result_set->unknown_attributes().size(), Eq(2));
}

INSTANTIATE_TEST_SUITE_P(CombinedCreateListTest, CreateListStepTest,
                         testing::Bool());

}  // namespace

}  // namespace google::api::expr::runtime
