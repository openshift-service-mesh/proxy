# What is CEL?

Common Expression Language (CEL) is an expression language that’s fast,
portable, and safe to execute in performance-critical applications. CEL is
designed to be embedded in an application, with application-specific extensions,
and is ideal for extending declarative configurations that your applications
might already use.

## What is covered in this Codelab?

This codelab is aimed at developers who would like to learn CEL to use services
that already support CEL. This Codelab covers common use cases. This codelab
doesn't cover how to integrate CEL into your own project. For a more in-depth
look at the language, semantics, and features see the
[CEL Language Definition on GitHub](https://github.com/google/cel-spec).

Some key areas covered are:

*   [Hello, World: Using CEL to evaluate a String](#hello-world)
*   [Creating variables](#creating-variables)
*   [Commutative logical AND/OR](#logical-andor)
*   [Adding custom functions](#custom-functions)

### Prerequisites

This codelab builds upon a basic understanding of Protocol Buffers and C++.

If you're not familiar with Protocol Buffers, the first exercise will give you a
sense of how CEL works, but because the more advanced examples use Protocol
Buffers as the input into CEL, they may be harder to understand. Consider
working through one of these tutorials, first. See the devsite for
[Protocol Buffers](https://protobuf.dev).

If you're not familiar with Bazel, Bazel is an open-source build and test tool
that supports multi-language projects and manages dependencies. This codelab and
`cel-cpp` are built using Bazel. To learn more about building C++ projects with
Bazel, see the official [Bazel C++ Tutorial](https://bazel.build/tutorials/cpp)
and the [Bazel Documentation](https://bazel.build/docs).

Notes on portability: Protocol Buffers are not required to use CEL generally,
but the C++ implementation has a hard dependency on the library and some APIs
reference protobuf types directly. Automated builds test against gcc10 and
clang14 on linux, a recent visual code version on Windows, and a recent xcode
version on MacOS. We accept requests for portability fixes for other OSes and
compilers, but don't actively maintain support at this time. A simple Docker
file is provided as a reference for a known good environment configuration for
running the codelab solutions.

What you'll need:

-   Git
-   Bazel
-   C/C++ Compiler (GCC, Clang, Visual Studio).
-   Optional: bazelisk is a wrapper around bazel that simplifies version
    management. If using, substitute all bazel commands below with `bazelisk`.

## GitHub Setup

GitHub Repo:

The code for this codelab lives in the `codelab` folder of the cel-cpp repo. The
solutions are available in the `codelab/solution` folder of the same repo.

Clone and cd into the repo:

```
git clone git@github.com:google/cel-cpp.git
cd cel-cpp
```

Make sure everything is working by building the codelab:

```
bazel build //codelab:all
```

## Setting up a Bazel Project with cel-cpp

If you want to integrate `cel-cpp` into your own standalone C++ project using
[Bazel](https://bazel.build/docs), you can manage it as an external dependency
with [Bzlmod](https://bazel.build/external/overview#bzlmod).

### MODULE.bazel

In your project's root `MODULE.bazel` file, declare a dependency on `cel-cpp`
from the
[Bazel Central Registry (BCR)](https://registry.bazel.build/modules/cel-cpp):

```python
bazel_dep(name = "cel-cpp", version = "<version>")
```

Alternatively, if you want to depend directly on a specific commit from the
GitHub repository, you can use `git_override`:

```python
bazel_dep(name = "cel-cpp", version = "0.0.0")
git_override(
    module_name = "cel-cpp",
    remote = "https://github.com/google/cel-cpp.git",
    commit = "<commit_hash>",
)
```

### BUILD

In your project's `BUILD` (or `BUILD.bazel`) file, reference `cel-cpp` targets
using `@cel-cpp//...`. For example, to compile a C++ binary that compiles and
evaluates CEL expressions using the modern `Compiler` and `Runtime` APIs shown
in this codelab:

```python
cc_binary(
    name = "my_cel_app",
    srcs = ["main.cc"],
    deps = [
        "@cel-cpp//checker:validation_result",
        "@cel-cpp//common:ast",
        "@cel-cpp//common:minimal_descriptor_pool",
        "@cel-cpp//common:value",
        "@cel-cpp//compiler",
        "@cel-cpp//compiler:compiler_factory",
        "@cel-cpp//compiler:standard_library",
        "@cel-cpp//runtime",
        "@cel-cpp//runtime:activation",
        "@cel-cpp//runtime:runtime_builder",
        "@cel-cpp//runtime:runtime_options",
        "@cel-cpp//runtime:standard_runtime_builder_factory",
    ],
)
```

## Hello, World

In the tried and true tradition of all programming languages, let's start with
"Hello, World!".

Update exercise1.cc with the following:

Using declarations:

```c++
using ::cel::Activation;
using ::cel::Compiler;
using ::cel::CompilerBuilder;
using ::cel::Program;
using ::cel::Runtime;
using ::cel::RuntimeBuilder;
using ::cel::RuntimeOptions;
using ::cel::ValidationResult;
using ::cel::Value;
```

Implementation:

```c++
absl::StatusOr<std::string> ParseAndEvaluate(absl::string_view cel_expr) {
  // === Start Codelab ===
  // Setup a default compiler for compiling expressions.
  CEL_ASSIGN_OR_RETURN(
      std::unique_ptr<CompilerBuilder> compiler_builder,
      cel::NewCompilerBuilder(cel::GetMinimalDescriptorPool()));
  CEL_RETURN_IF_ERROR(
      compiler_builder->AddLibrary(cel::StandardCompilerLibrary()));
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<Compiler> compiler,
                       std::move(compiler_builder)->Build());

  // Compile the expression.
  CEL_ASSIGN_OR_RETURN(ValidationResult validation_result,
                       compiler->Compile(cel_expr));
  if (!validation_result.IsValid()) {
    return absl::InvalidArgumentError(validation_result.FormatError());
  }

  // Setup a standard runtime for evaluating expressions.
  RuntimeOptions options;
  CEL_ASSIGN_OR_RETURN(
      RuntimeBuilder runtime_builder,
      cel::CreateStandardRuntimeBuilder(cel::GetMinimalDescriptorPool(),
                                        options));
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<Runtime> runtime,
                       std::move(runtime_builder).Build());

  // Build the executable program from the compiled AST.
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
                       validation_result.ReleaseAst());
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<Program> program,
                       runtime->CreateProgram(std::move(ast)));

  // The evaluator uses a proto Arena for allocations during evaluation.
  proto2::Arena arena;
  // The activation provides variables and functions bound into the
  // expression environment. In this example, there's no context expected, so
  // we provide an empty activation.
  Activation activation;

  // Run the program.
  CEL_ASSIGN_OR_RETURN(Value result,
                       program->Evaluate(&arena, activation));

  // Convert the result to a C++ string.
  return ConvertResult(result);
  // === End Codelab ===
}
```

Run the following to check your work:

```
bazel test //codelab:exercise1_test
```

You can add additional test cases or experiment with different return types.

Hello, World! Now, let's break down what's happening.

### Setup the Environment

CEL applications compile and evaluate an expression against an environment.

The standard CEL environment supports all of the types, operators, functions,
and macros defined within the language spec. The compiler and runtime objects
can be customized with other variables, types, and functions.

A `CompilerBuilder` configures the compilation environment, while a
`RuntimeBuilder` configures the execution environment:

```c++
#include "compiler/compiler_factory.h"
#include "compiler/standard_library.h"
#include "runtime/runtime_builder.h"
#include "runtime/runtime_options.h"
#include "runtime/standard_runtime_builder_factory.h"
...
// Create a compiler configured with the standard CEL library.
CEL_ASSIGN_OR_RETURN(
    std::unique_ptr<cel::CompilerBuilder> compiler_builder,
    cel::NewCompilerBuilder(cel::GetMinimalDescriptorPool()));
CEL_RETURN_IF_ERROR(
    compiler_builder->AddLibrary(cel::StandardCompilerLibrary()));
CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Compiler> compiler,
                     std::move(compiler_builder)->Build());

// Create a standard runtime.
cel::RuntimeOptions options;
CEL_ASSIGN_OR_RETURN(
    cel::RuntimeBuilder runtime_builder,
    cel::CreateStandardRuntimeBuilder(cel::GetMinimalDescriptorPool(),
                                      options));
CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Runtime> runtime,
                     std::move(runtime_builder).Build());
```

### Compile

After the compiler is configured, you can compile source expressions into a
checked `cel::Ast`:

```c++
#include "checker/validation_result.h"
// ...
CEL_ASSIGN_OR_RETURN(cel::ValidationResult validation_result,
                     compiler->Compile(cel_expr));
if (!validation_result.IsValid()) {
  return absl::InvalidArgumentError(validation_result.FormatError());
}
```

`compiler->Compile(...)` parses and type-checks the expression in one step,
returning a `cel::ValidationResult`. If the expression is valid
(`validation_result.IsValid()`), the resulting `cel::Ast` can be extracted using
`validation_result.ReleaseAst()`.

> Note: If you need to interface with external systems that store or transmit
> serialized protobuf ASTs (`google::api::expr::CheckedExpr`), conversion
> examples are available in `checked_expr_conversion_example.h`
> (`cel::AstToCheckedExpr` and `cel::CreateAstFromCheckedExpr`).

### Evaluate

Once a `cel::Ast` is compiled, `runtime->CreateProgram(...)` creates an
executable `cel::Program`. The program is then evaluated against a
`cel::Activation`, which provides per-evaluation bindings for variables and
functions in the environment:

```c++
#include "common/ast.h"
#include "runtime/activation.h"
#include "third_party/protobuf/arena.h"
...
// Build the executable program from the compiled AST.
CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
                     validation_result.ReleaseAst());
CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Program> program,
                     runtime->CreateProgram(std::move(ast)));

// Run the program against an activation and proto Arena.
cel::Activation activation;
proto2::Arena arena;
CEL_ASSIGN_OR_RETURN(cel::Value result,
                     program->Evaluate(&arena, activation));

return ConvertResult(result);
```

## Creating variables

Most CEL applications declare variables that can be referenced within
expressions. Variable declarations specify a name and a type. A variable's type
may be a CEL built-in type, a protocol buffer well-known type, or any protobuf
message type so long as its descriptor is registered.

At runtime, the hosting program binds variable values into `cel::Activation`.

For the C++ evaluator at runtime, values are represented by `cel::Value`.

Update exercise2.cc:

```c++
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
  proto2::Arena arena;
  // === Start Codelab ===
  activation.InsertOrAssignValue("bool_var", cel::BoolValue(bool_var));
  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
                       validation_result.ReleaseAst());
  return EvalAst(std::move(ast), activation, &arena);
}
```

Run the following to check your work. You should have fixed the first two test
cases in exercise2_test.cc.

```
bazel test //codelab:exercise2_test
```

The second overload uses a protocol buffer message (`AttributeContext`) to
represent the environment variables. For this use case,
`cel::BindProtoToActivation` automatically binds fields from a top-level message
into the activation (`#include
"runtime/bind_proto_to_activation.h"`):

```c++
#include "runtime/bind_proto_to_activation.h"
// ...
absl::StatusOr<bool> CompileAndEvaluateWithContext(
    absl::string_view cel_expr, const AttributeContext& context) {
  // ... compile cel_expr ...
  cel::Activation activation;
  proto2::Arena arena;
  // === Start Codelab ===
  CEL_RETURN_IF_ERROR(cel::BindProtoToActivation(
      context, cel::BindProtoUnsetFieldBehavior::kBindDefaultValue,
      proto2::DescriptorPool::generated_pool(),
      proto2::MessageFactory::generated_factory(), &arena, &activation));
  // === End Codelab ===

  CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Ast> ast,
                       validation_result.ReleaseAst());
  return EvalAst(std::move(ast), activation, &arena);
}
```

Note: You can experiment with unset values using
`cel::BindProtoUnsetFieldBehavior::kBindDefaultValue` or `kSkip`. With `kSkip`,
unset protobuf fields will not be bound at all, and accesses in expressions will
result in errors.

## Logical And/Or

One of CEL's more distinctive features is its use of commutative logical
operators. Either side of a conditional branch can short-circuit the evaluation,
even in the face of errors or partial input. Note: If you are skipping ahead,
copy the solution for exercise2 -- we'll be using it to test the behavior of
some simple expressions.

exercise3_test.cc lists truth tables for simple expressions using the 'or',
'and', and 'ternary' operators.

Running the following should result in some failing expectations.

```
bazel test //codelab:exercise3_test
```

Open exercise3_test.cc in your editor:

```c++
TEST(Exercise3Var, LogicalOr) {
  // Some of these expectations are incorrect.
  // If a logical operation can short-circuit a branch that results in an error,
  // CEL evaluation will return the logical result instead of propagating the
  // error. For logical or, this means if one branch is true, the result will
  // always be true, regardless of the other branch.
  // Wrong
  EXPECT_THAT(TruthTableTest("true || (1 / 0 > 2)"),
              StatusIs(absl::StatusCode::kInvalidArgument, "divide by zero"));
  EXPECT_THAT(TruthTableTest("false || (1 / 0 > 2)"),
              StatusIs(absl::StatusCode::kInvalidArgument, "divide by zero"));
  // Wrong
  EXPECT_THAT(TruthTableTest("(1 / 0 > 2) || true"),
              StatusIs(absl::StatusCode::kInvalidArgument, "divide by zero"));
  EXPECT_THAT(TruthTableTest("(1 / 0 > 2) || false"),
              StatusIs(absl::StatusCode::kInvalidArgument, "divide by zero"));
  EXPECT_THAT(TruthTableTest("(1 / 0 > 2) || (1 / 0 > 2)"),
              StatusIs(absl::StatusCode::kInvalidArgument, "divide by zero"));
  EXPECT_THAT(TruthTableTest("true || true"), IsOkAndHolds(true));
  EXPECT_THAT(TruthTableTest("true || false"), IsOkAndHolds(true));
  EXPECT_THAT(TruthTableTest("false || true"), IsOkAndHolds(true));
  EXPECT_THAT(TruthTableTest("false || false"), IsOkAndHolds(false));
}
```

Updating the two failing cases "true || (1 / 0 > 2)" and "(1 / 0 > 2) || true"
should fix this test:

```c++
// ...
  // Correct
  EXPECT_THAT(TruthTableTest("true || (1 / 0 > 2)"),
              IsOkAndHolds(true));
  EXPECT_THAT(TruthTableTest("false || (1 / 0 > 2)"),
              StatusIs(absl::StatusCode::kInvalidArgument, "divide by zero"));
  // Correct
  EXPECT_THAT(TruthTableTest("(1 / 0 > 2) || true"),
              IsOkAndHolds(true));
```

You can examine the other tests for other cases for corresponding behavior for
the 'and' and ternary operators.

CEL finds an evaluation order which gives results whenever possible, ignoring
errors or even missing data that might occur in other evaluation orders.
Applications like IAM conditions rely on this property to minimize the cost of
evaluation, deferring the gathering of expensive inputs when a result can be
reached without them.

## Adding custom functions {#custom-functions}

See `exercise4.h` and `exercise4.cc`. Documentation to be added later.
