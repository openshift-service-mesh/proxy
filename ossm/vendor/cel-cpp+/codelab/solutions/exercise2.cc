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

#include "codelab/exercise2.h"

#include <memory>
#include <utility>

#include "google/rpc/context/attribute_context.pb.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "checker/type_checker_builder.h"
#include "checker/validation_result.h"
#include "common/ast.h"
#include "common/decl.h"
#include "common/type.h"
#include "common/value.h"
#include "compiler/compiler.h"
#include "compiler/compiler_factory.h"
#include "compiler/standard_library.h"
#include "internal/status_macros.h"
#include "runtime/activation.h"
#include "runtime/bind_proto_to_activation.h"
#include "runtime/runtime.h"
#include "runtime/runtime_builder.h"
#include "runtime/runtime_options.h"
#include "runtime/standard_runtime_builder_factory.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"

namespace cel_codelab {
namespace {

using ::google::rpc::context::AttributeContext;

absl::StatusOr<std::unique_ptr<cel::Compiler>> MakeCelCompiler() {
  // Note: we are using the generated descriptor pool here for simplicity, but
  // it has the drawback of including all message types that are linked into the
  // binary instead of just the ones expected for the CEL environment.
  google::protobuf::LinkMessageReflection<AttributeContext>();
  CEL_ASSIGN_OR_RETURN(
      std::unique_ptr<cel::CompilerBuilder> builder,
      cel::NewCompilerBuilder(google::protobuf::DescriptorPool::generated_pool()));

  CEL_RETURN_IF_ERROR(builder->AddLibrary(cel::StandardCompilerLibrary()));
  // === Start Codelab ===
  cel::TypeCheckerBuilder& checker_builder = builder->GetCheckerBuilder();
  CEL_RETURN_IF_ERROR(checker_builder.AddVariable(
      cel::MakeVariableDecl("bool_var", cel::BoolType())));
  CEL_RETURN_IF_ERROR(checker_builder.AddContextDeclaration(
      AttributeContext::descriptor()->full_name()));
  // === End Codelab ===

  return std::move(builder)->Build();
}

// Evaluate a runtime cel::Ast against the given activation and arena.
absl::StatusOr<bool> EvalAst(std::unique_ptr<cel::Ast> ast,
                             const cel::Activation& activation,
                             google::protobuf::Arena* arena) {
  // Setup a default standard runtime.
  cel::RuntimeOptions options;
  CEL_ASSIGN_OR_RETURN(cel::RuntimeBuilder runtime_builder,
                       cel::CreateStandardRuntimeBuilder(
                           google::protobuf::DescriptorPool::generated_pool(), options));
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Runtime> runtime,
                       std::move(runtime_builder).Build());

  // Note, the program plan below is reusable across different inputs, but we
  // create one just in time for evaluation here.
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Program> program,
                       runtime->CreateProgram(std::move(ast)));

  CEL_ASSIGN_OR_RETURN(cel::Value result, program->Evaluate(arena, activation));

  if (result.IsBool()) {
    return result.GetBool().NativeValue();
  }
  if (result.IsError()) {
    return result.GetError().ToStatus();
  }
  return absl::InvalidArgumentError(
      absl::StrCat("expected 'bool' result got '", result.GetTypeName(), "'"));
}

}  // namespace

absl::StatusOr<bool> CompileAndEvaluateWithBoolVar(absl::string_view cel_expr,
                                                   bool bool_var) {
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Compiler> compiler,
                       MakeCelCompiler());

  CEL_ASSIGN_OR_RETURN(cel::ValidationResult validation_result,
                       compiler->Compile(cel_expr));
  if (!validation_result.IsValid()) {
    return absl::InvalidArgumentError(validation_result.FormatError());
  }

  cel::Activation activation;
  google::protobuf::Arena arena;
  // === Start Codelab ===
  activation.InsertOrAssignValue("bool_var", cel::BoolValue(bool_var));
  // === End Codelab ===

  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
                       validation_result.ReleaseAst());
  return EvalAst(std::move(ast), activation, &arena);
}

absl::StatusOr<bool> CompileAndEvaluateWithContext(
    absl::string_view cel_expr, const AttributeContext& context) {
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Compiler> compiler,
                       MakeCelCompiler());

  CEL_ASSIGN_OR_RETURN(cel::ValidationResult validation_result,
                       compiler->Compile(cel_expr));
  if (!validation_result.IsValid()) {
    return absl::InvalidArgumentError(validation_result.FormatError());
  }

  cel::Activation activation;
  google::protobuf::Arena arena;
  // === Start Codelab ===
  CEL_RETURN_IF_ERROR(cel::BindProtoToActivation(
      context, cel::BindProtoUnsetFieldBehavior::kBindDefaultValue,
      google::protobuf::DescriptorPool::generated_pool(),
      google::protobuf::MessageFactory::generated_factory(), &arena, &activation));
  // === End Codelab ===

  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
                       validation_result.ReleaseAst());
  return EvalAst(std::move(ast), activation, &arena);
}

}  // namespace cel_codelab
