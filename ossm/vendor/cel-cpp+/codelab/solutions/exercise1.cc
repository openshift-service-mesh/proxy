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

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "checker/validation_result.h"
#include "common/ast.h"
#include "common/minimal_descriptor_pool.h"
#include "common/value.h"
#include "compiler/compiler.h"
#include "compiler/compiler_factory.h"
#include "compiler/standard_library.h"
#include "internal/status_macros.h"
#include "runtime/activation.h"
#include "runtime/runtime.h"
#include "runtime/runtime_builder.h"
#include "runtime/runtime_options.h"
#include "runtime/standard_runtime_builder_factory.h"
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
  // Setup a default compiler for compiling expressions.
  CEL_ASSIGN_OR_RETURN(
      std::unique_ptr<cel::CompilerBuilder> compiler_builder,
      cel::NewCompilerBuilder(cel::GetMinimalDescriptorPool()));
  CEL_RETURN_IF_ERROR(
      compiler_builder->AddLibrary(cel::StandardCompilerLibrary()));
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Compiler> compiler,
                       std::move(compiler_builder)->Build());

  // Compile the expression.
  CEL_ASSIGN_OR_RETURN(cel::ValidationResult validation_result,
                       compiler->Compile(cel_expr));
  if (!validation_result.IsValid()) {
    return absl::InvalidArgumentError(validation_result.FormatError());
  }

  // Setup a standard runtime for evaluating expressions.
  cel::RuntimeOptions options;
  CEL_ASSIGN_OR_RETURN(cel::RuntimeBuilder runtime_builder,
                       cel::CreateStandardRuntimeBuilder(
                           cel::GetMinimalDescriptorPool(), options));
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Runtime> runtime,
                       std::move(runtime_builder).Build());

  // Build the executable program from the compiled AST.
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
                       validation_result.ReleaseAst());
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Program> program,
                       runtime->CreateProgram(std::move(ast)));

  // The evaluator uses a proto Arena for allocations during evaluation.
  google::protobuf::Arena arena;
  // The activation provides variables and functions bound into the
  // expression environment. In this example, there's no context expected, so
  // we provide an empty activation.
  cel::Activation activation;

  // Run the program.
  CEL_ASSIGN_OR_RETURN(cel::Value result,
                       program->Evaluate(&arena, activation));

  // Convert the result to a C++ string.
  return ConvertResult(result);
  // === End Codelab ===
}

}  // namespace cel_codelab
