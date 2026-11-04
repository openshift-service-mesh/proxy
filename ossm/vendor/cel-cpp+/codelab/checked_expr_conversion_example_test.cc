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

#include "codelab/checked_expr_conversion_example.h"

#include <memory>
#include <utility>

#include "cel/expr/checked.pb.h"
#include "absl/status/status_matchers.h"
#include "checker/validation_result.h"
#include "common/ast.h"
#include "compiler/compiler.h"
#include "compiler/compiler_factory.h"
#include "compiler/standard_library.h"
#include "internal/testing.h"
#include "google/protobuf/descriptor.h"

namespace cel_codelab {
namespace {

using ::absl_testing::IsOk;

TEST(CheckedExprConversionExampleTest, ConvertAstToCheckedExprAndBack) {
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<cel::CompilerBuilder> builder,
      cel::NewCompilerBuilder(google::protobuf::DescriptorPool::generated_pool()));
  ASSERT_THAT(builder->AddLibrary(cel::StandardCompilerLibrary()), IsOk());
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<cel::Compiler> compiler,
                       std::move(builder)->Build());

  ASSERT_OK_AND_ASSIGN(cel::ValidationResult validation_result,
                       compiler->Compile("1 + 2 == 3"));
  ASSERT_TRUE(validation_result.IsValid());
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<cel::Ast> ast,
                       validation_result.ReleaseAst());

  // Convert cel::Ast to CheckedExpr proto
  ASSERT_OK_AND_ASSIGN(cel::expr::CheckedExpr checked_expr,
                       ConvertAstToCheckedExpr(*ast));

  // Convert CheckedExpr proto back to cel::Ast
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<cel::Ast> roundtrip_ast,
                       ConvertCheckedExprToAst(checked_expr));
  EXPECT_NE(roundtrip_ast, nullptr);
}

}  // namespace
}  // namespace cel_codelab
