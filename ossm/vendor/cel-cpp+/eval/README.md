# CEL Evaluator

A C++ implementation of a [Common Expression Language][1] evaluator.

## Migrating to cel::Value APIs

New users should prefer using the `cel::Value` APIs ("Modern"). The
`google::api::expr::runtime::CelValue` APIs ("Legacy") are not formally
deprecated at this time, but they now incur some overhead and will not be
updated to support all new features. Internally, both flavors use the same
underlying implementation based on the cel::Value representation.

### When to Migrate

If your integration is stable and you don't need access to newer features there
is no need to migrate at this time.

If you need to add support for optionals or other custom opaque or struct types
you must migrate.

If you need to interactively evaluate from source, you should migrate to avoid
extra proto serialization costs.

### How to Migrate

#### 1. Header, Namespace, and Build Target Mapping

Concept                        | Legacy API (`google::api::expr::runtime`)                                                                                                                                                              | Modern API (`cel`)
:----------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-----------------
**Namespace**                  | `google::api::expr::runtime`                                                                                                                                                                           | `cel`
**Runtime & Program Creation** | `#include "eval/public/cel_expression.h"`<br>`#include "eval/public/cel_expr_builder_factory.h"`<br>Target: `//eval/public:cel_expression` | `#include "runtime/runtime.h"`<br>`#include "runtime/standard_runtime_builder_factory.h"`<br>Targets: `//runtime`, `//runtime:standard_runtime_builder_factory`
**Value Representation**       | `#include "eval/public/cel_value.h"`<br>Target: `//eval/public:cel_value`                                                                                      | `#include "common/value.h"`<br>Target: `//common:value`
**Activation & Variables**     | `#include "eval/public/activation.h"`<br>Target: `//eval/public:activation`                                                                                    | `#include "runtime/activation.h"`<br>Target: `//runtime:activation`
**Proto Activation Binding**   | `#include "eval/public/activation_bind_helper.h"`<br>Target: `//eval/public:activation_bind_helper`                                                            | `#include "runtime/bind_proto_to_activation.h"`<br>Target: `//runtime:bind_proto_to_activation`
**Function Adapters**          | `#include "eval/public/cel_function_adapter.h"`                                                                                                                                    | `#include "runtime/function_adapter.h"`
**Interoperability Adapters**  | N/A                                                                                                                                                                                                    | `#include "common/legacy_value.h"`<br>Target: `//common:legacy_value`

#### 2. Runtime Creation and AST Planning (`CelExpressionBuilder` vs `cel::Runtime`)

In the legacy API, `CelExpressionBuilder` created expression plans from
`google::api::expr::CheckedExpr` protobufs. In the modern API, `cel::Runtime`
creates reusable `cel::Program` instances directly from `cel::Ast` objects
without requiring protobuf serialization round-trips.

**Legacy (`google::api::expr::runtime::CelExpressionBuilder`)**:

```cpp
using ::google::api::expr::runtime::CelExpressionBuilder;
using ::google::api::expr::runtime::CreateCelExpressionBuilder;
using ::google::api::expr::runtime::InterpreterOptions;
using ::google::api::expr::runtime::RegisterBuiltinFunctions;

InterpreterOptions options;
std::unique_ptr<CelExpressionBuilder> builder =
    CreateCelExpressionBuilder(descriptor_pool, message_factory, options);
CEL_RETURN_IF_ERROR(RegisterBuiltinFunctions(builder->GetRegistry(), options));

// Requires serializing or passing a google::api::expr::CheckedExpr proto
CEL_ASSIGN_OR_RETURN(std::unique_ptr<CelExpression> plan,
                     builder->CreateExpression(&checked_expr_proto));
```

**Modern (`cel::Runtime`)**:

```cpp
#include "runtime/runtime.h"
#include "runtime/runtime_options.h"
#include "runtime/standard_runtime_builder_factory.h"

cel::RuntimeOptions options;
CEL_ASSIGN_OR_RETURN(
    cel::RuntimeBuilder runtime_builder,
    cel::CreateStandardRuntimeBuilder(descriptor_pool, options));
CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Runtime> runtime,
                     std::move(runtime_builder).Build());

// Create program directly from a cel::Ast (e.g., from compiler->Compile(expr))
CEL_ASSIGN_OR_RETURN(std::unique_ptr<cel::Program> program,
                     runtime->CreateProgram(std::move(ast)));
```

*Note on AST Conversion*: If your architecture persists or receives serialized
`google::api::expr::CheckedExpr` protobufs, convert them to `cel::Ast` using
`cel::CreateAstFromCheckedExpr(checked_expr_proto)` (`#include
"common/ast_proto.h"`, target
`//common:ast_proto`).

#### 3. Creating, Inspecting, and Unpacking Values (`CelValue` vs `cel::Value`)

**Legacy (`google::api::expr::runtime::CelValue`)**:

```cpp
#include "eval/public/cel_value.h"

using ::google::api::expr::runtime::CelValue;

// Creation
CelValue bool_val = CelValue::CreateBool(true);
CelValue int_val = CelValue::CreateInt64(42);
CelValue str_val = CelValue::CreateStringView("hello");

// Inspection & Unpacking
if (bool_val.IsBool()) {
  bool b;
  bool_val.GetValue(&b);
}
```

**Modern (`cel::Value`)**:

```cpp
#include "common/value.h"

// Creation
cel::Value bool_val = cel::BoolValue(true);
cel::Value int_val = cel::IntValue(42);
cel::Value str_val = cel::StringValue("hello");

// Inspection & Unpacking
if (bool_val.IsBool()) {
  bool b = bool_val.GetBool().NativeValue();
} else if (str_val.IsString()) {
  std::string s = str_val.GetString().ToString();
} else if (str_val.IsError()) {
  absl::Status status = str_val.GetError().ToStatus();
}
```

#### 4. Activation and Protobuf Binding (`BindProtoToActivation`)

The modern equivalent of `activation_bind_helper.h` is
`runtime/bind_proto_to_activation.h`.

**Legacy**:

```cpp
#include "eval/public/activation.h"
#include "eval/public/activation_bind_helper.h"

using ::google::api::expr::runtime::Activation;
using ::google::api::expr::runtime::BindProtoToActivation;
using ::google::api::expr::runtime::ProtoUnsetFieldOptions;

Activation activation;
activation.InsertValue("bool_var", CelValue::CreateBool(true));
CEL_RETURN_IF_ERROR(BindProtoToActivation(
    &context_message, &arena, &activation, ProtoUnsetFieldOptions::kBindDefault));
```

**Modern**:

```cpp
#include "runtime/activation.h"
#include "runtime/bind_proto_to_activation.h"

cel::Activation activation;
activation.InsertOrAssignValue("bool_var", cel::BoolValue(true));
CEL_RETURN_IF_ERROR(cel::BindProtoToActivation(
    context_message, cel::BindProtoUnsetFieldBehavior::kBindDefaultValue,
    descriptor_pool, message_factory, &arena, &activation));
```

#### 5. Program Evaluation

Notice the parameter order change when calling `Evaluate`: `(&arena,
activation)` instead of `(activation, &arena)`.

**Legacy**:

```cpp
CEL_ASSIGN_OR_RETURN(CelValue result, plan->Evaluate(activation, &arena));
```

**Modern**:

```cpp
CEL_ASSIGN_OR_RETURN(cel::Value result, program->Evaluate(&arena, activation));
```

#### 6. Custom Extension Functions (`FunctionAdapter`)

**Legacy (`google::api::expr::runtime::FunctionAdapter`)**:

```cpp
#include "eval/public/cel_function_adapter.h"

using AdapterT = google::api::expr::runtime::FunctionAdapter<
    absl::StatusOr<bool>, const CelMap*, CelValue::StringHolder, CelValue>;
CEL_RETURN_IF_ERROR(AdapterT::CreateAndRegister(
    "contains", /*receiver_style=*/true, &ContainsFunc, builder->GetRegistry()));
```

**Modern (`cel::FunctionAdapter` / `cel::{arity}FunctionAdapter`)**:

```cpp
#include "runtime/function_adapter.h"

using AdapterT = cel::TernaryFunctionAdapter<
    absl::StatusOr<bool>, const cel::MapValue&, const cel::StringValue&, const cel::Value&>;
CEL_RETURN_IF_ERROR(AdapterT::RegisterMemberOverload(
    "contains", &ContainsFunc, runtime_builder.function_registry()));
```

### Other behavior notes

There is limited support for interoperability when migrating incrementally. You
can use `#include "common/legacy_value.h"` (build target
`//common:legacy_value`) to adapt compatible value types
across legacy and modern boundaries:

*   **Adapting Legacy `CelValue` to Modern `cel::Value`**:

    ```cpp
    #include "common/legacy_value.h"

    CEL_ASSIGN_OR_RETURN(cel::Value modern_val,
                         cel::ModernValue(&arena, legacy_cel_val));
    ```

*   **Adapting Modern `cel::Value` to Legacy `CelValue`**:

    ```cpp
    #include "common/legacy_value.h"

    CEL_ASSIGN_OR_RETURN(google::api::expr::runtime::CelValue legacy_val,
                         cel::LegacyValue(&arena, modern_val));
    ```

Legacy style extension functions use the interop helpers implicitly and can be
used with modern APIs. `google::api::expr::runtime::CelFunction` is also a
`cel::Function`.

```cpp
std::unique_ptr<google::api::expr::runtime::CelFunction> ext_func = ...;

cel::FunctionDescriptor descriptor = ext_func->descriptor();
CEL_RETURN_IF_ERROR(
  runtime_builder.function_registry().Register(
    descriptor, std::move(ext_func)));
```

Important: The interop code does not support adapting new types introduced with
`cel::Value` to `google::api::expr::runtime::CelValue`. This means you should
not use any of the legacy APIs if your expressions refer to values with an
optional, custom (non-protobuf) struct, or custom opaque type.

[1]:  https://github.com/cel-expr/cel-spec
