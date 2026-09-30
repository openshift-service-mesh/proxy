// Copyright 2021 Google LLC
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

#include "codelab/exercise1.h"

#include <memory>  // IWYU pragma: keep
#include <string>
#include <utility>  // IWYU pragma: keep

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "checker/validation_result.h"  // IWYU pragma: keep, needed for codelab solution
#include "common/ast.h"  // IWYU pragma: keep
#include "common/minimal_descriptor_pool.h"  // IWYU pragma: keep
#include "common/value.h"
#include "compiler/compiler.h"          // IWYU pragma: keep
#include "compiler/compiler_factory.h"  // IWYU pragma: keep
#include "compiler/standard_library.h"  // IWYU pragma: keep
#include "internal/status_macros.h"     // IWYU pragma: keep
#include "runtime/activation.h"
#include "runtime/runtime.h"          // IWYU pragma: keep
#include "runtime/runtime_builder.h"  // IWYU pragma: keep
#include "runtime/runtime_options.h"  // IWYU pragma: keep
#include "runtime/standard_runtime_builder_factory.h"  // IWYU pragma: keep
#include "google/protobuf/arena.h"

namespace cel_codelab {
namespace {

// Convert the cel::Value to a C++ string if it is string typed. Otherwise,
// return invalid argument error.
absl::StatusOr<std::string> ConvertResult(const cel::Value& value) {
  if (value.IsString()) {
    return value.GetString().ToString();
  }
  return absl::InvalidArgumentError(
      absl::StrCat("expected string result got '", value.GetTypeName(), "'"));
}

}  // namespace

absl::StatusOr<std::string> ParseAndEvaluate(absl::string_view cel_expr) {
  // === Start Codelab ===
  // 1. Setup a default compiler for compiling expressions:
  //    Use cel::NewCompilerBuilder(cel::GetMinimalDescriptorPool()) and add
  //    cel::StandardCompilerLibrary(). Build the cel::Compiler.

  // 2. Compile the expression using compiler->Compile(cel_expr).
  //    Check that the resulting validation_result.IsValid().

  // 3. Setup a standard runtime for evaluating expressions:
  //    Use cel::CreateStandardRuntimeBuilder(cel::GetMinimalDescriptorPool(),
  //    options) and build the cel::Runtime.

  // 4. Create an executable program from the compiled AST:
  //    Use CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
  //                             validation_result.ReleaseAst()) and
  //    runtime->CreateProgram(std::move(ast)).

  // The evaluator uses a proto Arena for allocations during evaluation.
  google::protobuf::Arena arena;
  // The activation provides variables and functions bound into the
  // expression environment. In this example, there's no context expected, so
  // we provide an empty activation.
  cel::Activation activation;
  (void)arena;
  (void)activation;

  // 5. Evaluate the program and convert the result:
  //    Call program->Evaluate(&arena, activation) and pass the resulting
  //    cel::Value to ConvertResult.
  return absl::UnimplementedError("Not yet implemented");
  // === End Codelab ===
}

}  // namespace cel_codelab
