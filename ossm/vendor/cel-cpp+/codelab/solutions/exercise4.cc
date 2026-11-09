// Copyright 2022 Google LLC
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

#include "codelab/exercise4.h"

#include <memory>
#include <utility>

#include "google/rpc/context/attribute_context.pb.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
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
#include "runtime/function_adapter.h"
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

absl::StatusOr<bool> ContainsExtensionFunction(
    const cel::MapValue& map, const cel::StringValue& key,
    const cel::Value& value, const google::protobuf::DescriptorPool* descriptor_pool,
    google::protobuf::MessageFactory* message_factory, google::protobuf::Arena* arena) {
  CEL_ASSIGN_OR_RETURN(absl::optional<cel::Value> entry,
                       map.Find(key, descriptor_pool, message_factory, arena));
  if (!entry.has_value()) {
    return false;
  }
  CEL_ASSIGN_OR_RETURN(cel::Value equal, entry->Equal(value, descriptor_pool,
                                                      message_factory, arena));
  return equal.IsBool() && equal.GetBool().NativeValue();
}

absl::StatusOr<std::unique_ptr<cel::Compiler>> MakeConfiguredCompiler() {
  // Setup for handling protobuf types.
  google::protobuf::LinkMessageReflection<AttributeContext>();
  CEL_ASSIGN_OR_RETURN(
      std::unique_ptr<cel::CompilerBuilder> builder,
      cel::NewCompilerBuilder(google::protobuf::DescriptorPool::generated_pool()));
  CEL_RETURN_IF_ERROR(builder->AddLibrary(cel::StandardCompilerLibrary()));
  // Adds fields of AttributeContext as variables.
  CEL_RETURN_IF_ERROR(builder->GetCheckerBuilder().AddContextDeclaration(
      AttributeContext::descriptor()->full_name()));

  // Codelab part 1:
  // Add a declaration for the map<string, V>.contains(string, V) function.
  auto& checker_builder = builder->GetCheckerBuilder();
  // Note: we use MakeMemberOverloadDecl instead of MakeOverloadDecl
  // because the function is receiver style, meaning that it is called as
  // e1.f(e2) instead of f(e1, e2).
  CEL_ASSIGN_OR_RETURN(
      cel::FunctionDecl decl,
      cel::MakeFunctionDecl(
          "contains",
          cel::MakeMemberOverloadDecl(
              "map_contains_string_value", cel::BoolType(),
              cel::MapType(checker_builder.arena(), cel::StringType(),
                           cel::TypeParamType("V")),
              cel::StringType(), cel::TypeParamType("V"))));
  // Note: we use MergeFunction instead of AddFunction because we are adding
  // an overload to an already declared function with the same name.
  CEL_RETURN_IF_ERROR(checker_builder.MergeFunction(decl));
  return std::move(builder)->Build();
}

class Evaluator {
 public:
  Evaluator() = default;

  absl::Status SetupEvaluatorEnvironment() {
    cel::RuntimeOptions options;
    CEL_ASSIGN_OR_RETURN(
        cel::RuntimeBuilder runtime_builder,
        cel::CreateStandardRuntimeBuilder(
            google::protobuf::DescriptorPool::generated_pool(), options));
    // Codelab part 2:
    // Register the map.contains(string, value) function.
    // Hint: use `TernaryFunctionAdapter::RegisterMemberOverload` to adapt
    // from a free function ContainsExtensionFunction.
    using AdapterT =
        cel::TernaryFunctionAdapter<absl::StatusOr<bool>, const cel::MapValue&,
                                    const cel::StringValue&, const cel::Value&>;
    CEL_RETURN_IF_ERROR(
        AdapterT::RegisterMemberOverload("contains", &ContainsExtensionFunction,
                                         runtime_builder.function_registry()));
    CEL_ASSIGN_OR_RETURN(runtime_, std::move(runtime_builder).Build());
    return absl::OkStatus();
  }

  absl::StatusOr<bool> Evaluate(std::unique_ptr<cel::Ast> ast,
                                const AttributeContext& context) {
    cel::Activation activation;
    CEL_RETURN_IF_ERROR(cel::BindProtoToActivation(
        context, cel::BindProtoUnsetFieldBehavior::kBindDefaultValue,
        google::protobuf::DescriptorPool::generated_pool(),
        google::protobuf::MessageFactory::generated_factory(), &arena_, &activation));

    CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Program> program,
                         runtime_->CreateProgram(std::move(ast)));
    CEL_ASSIGN_OR_RETURN(cel::Value result,
                         program->Evaluate(&arena_, activation));

    if (result.IsBool()) {
      return result.GetBool().NativeValue();
    }
    if (result.IsError()) {
      return result.GetError().ToStatus();
    }
    return absl::InvalidArgumentError(
        absl::StrCat("unexpected return type: ", result.GetTypeName()));
  }

 private:
  google::protobuf::Arena arena_;
  std::unique_ptr<cel::Runtime> runtime_;
};

}  // namespace

absl::StatusOr<bool> EvaluateWithExtensionFunction(
    absl::string_view expr, const AttributeContext& context) {
  // Prepare a checked expression.
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Compiler> compiler,
                       MakeConfiguredCompiler());
  CEL_ASSIGN_OR_RETURN(cel::ValidationResult validation_result,
                       compiler->Compile(expr));
  if (!validation_result.IsValid()) {
    return absl::InvalidArgumentError(validation_result.FormatError());
  }

  // Prepare an evaluation environment.
  Evaluator evaluator;
  CEL_RETURN_IF_ERROR(evaluator.SetupEvaluatorEnvironment());

  // Evaluate the checked AST against a particular activation.
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
                       validation_result.ReleaseAst());
  return evaluator.Evaluate(std::move(ast), context);
}

}  // namespace cel_codelab
