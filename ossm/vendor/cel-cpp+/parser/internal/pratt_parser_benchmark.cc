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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/absl_check.h"
#include "absl/strings/str_cat.h"
#include "common/source.h"
#include "internal/benchmark.h"
#include "parser/internal/pratt_parser.h"
#include "parser/options.h"
#include "parser/parser.h"
#include "parser/parser_interface.h"

namespace cel::parser_internal {
namespace {

enum class ParserImplType {
  kPratt,
  kAntlr,
};

std::unique_ptr<cel::Parser> CreateParser(ParserImplType type,
                                          cel::ParserOptions options) {
  options.max_recursion_depth = 512;
  std::unique_ptr<cel::ParserBuilder> builder;
  if (type == ParserImplType::kPratt) {
    builder = NewPrattParserBuilder(options);
  } else {
    builder = cel::NewParserBuilder(options);
  }
  auto parser = builder->Build();
  ABSL_DCHECK_OK(parser.status());
  return std::move(*parser);
}

// -----------------------------------------------------------------------------
// Workload 1: Common Representative CEL Expressions
// -----------------------------------------------------------------------------
void BM_ParseCommon(benchmark::State& state, ParserImplType type) {
  cel::ParserOptions options;
  options.enable_optional_syntax = true;
  options.enable_quoted_identifiers = true;
  auto parser = CreateParser(type, options);

  const std::vector<std::string> test_cases = {
      "x * 2 + y / 3",
      "foo.bar.baz(1, 2, \"abc\")",
      "a > 5 && b < 10 || c == \"xyz\"",
      "x ? y : z",
      "{\"foo\": 1, \"bar\": [2, 3]}",
      "has(foo.bar) && [1, 2, 3].all(x, x > 0)",
  };

  for (auto _ : state) {
    for (const auto& expr : test_cases) {
      auto source = cel::NewSource(expr);
      ABSL_DCHECK_OK(source.status());
      auto ast = parser->Parse(**source);
      ABSL_DCHECK_OK(ast.status());
      benchmark::DoNotOptimize(ast);
    }
  }
}

void BM_Pratt_ParseCommon(benchmark::State& state) {
  BM_ParseCommon(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseCommon(benchmark::State& state) {
  BM_ParseCommon(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseCommon);
BENCHMARK(BM_Antlr_ParseCommon);

// -----------------------------------------------------------------------------
// Workload 2: Deep Left-Associative Arithmetic Chains ("a + a + a...")
// -----------------------------------------------------------------------------
std::string BuildArithmeticChain(int length) {
  std::string expr = "a";
  for (int i = 1; i < length; ++i) {
    absl::StrAppend(&expr, " + a");
  }
  return expr;
}

void BM_ParseArithmeticChain(benchmark::State& state, ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildArithmeticChain(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK_OK(ast.status());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseArithmeticChain(benchmark::State& state) {
  BM_ParseArithmeticChain(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseArithmeticChain(benchmark::State& state) {
  BM_ParseArithmeticChain(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseArithmeticChain)->Arg(10)->Arg(50)->Arg(100);
BENCHMARK(BM_Antlr_ParseArithmeticChain)->Arg(10)->Arg(50)->Arg(100);

// -----------------------------------------------------------------------------
// Workload 3: Wide Logical Expression Chains ("a || a || a...")
// -----------------------------------------------------------------------------
std::string BuildLogicalChain(int length) {
  std::string expr = "a";
  for (int i = 1; i < length; ++i) {
    absl::StrAppend(&expr, " || a");
  }
  return expr;
}

void BM_ParseLogicalChain(benchmark::State& state, ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildLogicalChain(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK_OK(ast.status());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseLogicalChain(benchmark::State& state) {
  BM_ParseLogicalChain(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseLogicalChain(benchmark::State& state) {
  BM_ParseLogicalChain(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseLogicalChain)->Arg(10)->Arg(50)->Arg(100);
BENCHMARK(BM_Antlr_ParseLogicalChain)->Arg(10)->Arg(50)->Arg(100);

// -----------------------------------------------------------------------------
// Workload 4: Deep Member Access Chains ("a.f.f.f...")
// -----------------------------------------------------------------------------
std::string BuildMemberChain(int length) {
  std::string expr = "a";
  for (int i = 1; i < length; ++i) {
    absl::StrAppend(&expr, ".f");
  }
  return expr;
}

void BM_ParseMemberChain(benchmark::State& state, ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildMemberChain(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK_OK(ast.status());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseMemberChain(benchmark::State& state) {
  BM_ParseMemberChain(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseMemberChain(benchmark::State& state) {
  BM_ParseMemberChain(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseMemberChain)->Arg(10)->Arg(50)->Arg(100);
BENCHMARK(BM_Antlr_ParseMemberChain)->Arg(10)->Arg(50)->Arg(100);

// -----------------------------------------------------------------------------
// Workload 5: Deeply Nested Parentheses ("(((((a)))))")
// -----------------------------------------------------------------------------
std::string BuildNestedParentheses(int depth) {
  std::string prefix(depth, '(');
  std::string suffix(depth, ')');
  return absl::StrCat(prefix, "a", suffix);
}

void BM_ParseNestedParentheses(benchmark::State& state, ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildNestedParentheses(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK_OK(ast.status());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseNestedParentheses(benchmark::State& state) {
  BM_ParseNestedParentheses(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseNestedParentheses(benchmark::State& state) {
  BM_ParseNestedParentheses(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseNestedParentheses)->Arg(10)->Arg(50);
BENCHMARK(BM_Antlr_ParseNestedParentheses)->Arg(10)->Arg(50);

// -----------------------------------------------------------------------------
// Workload 6: Common Representative Expressions with Syntax Errors
// -----------------------------------------------------------------------------
void BM_ParseCommonSyntaxErrors(benchmark::State& state, ParserImplType type) {
  cel::ParserOptions options;
  options.enable_optional_syntax = true;
  options.enable_quoted_identifiers = true;
  auto parser = CreateParser(type, options);

  const std::vector<std::string> test_cases = {
      "x * 2 + y /",
      "foo.bar.baz(1, 2, \"abc\"",
      "a > 5 && && b < 10 || c == \"xyz\"",
      "x ? y :",
      "{\"foo\": 1, \"bar\": [2, 3",
      "has(foo.bar) && [1, 2, 3].all(x, +)",
      "a. + b",
      "Msg{f 10}",
      "(1 + 2 * (3 + )",
  };

  for (auto _ : state) {
    for (const auto& expr : test_cases) {
      auto source = cel::NewSource(expr);
      ABSL_DCHECK_OK(source.status());
      auto ast = parser->Parse(**source);
      ABSL_DCHECK(!ast.ok());
      benchmark::DoNotOptimize(ast);
    }
  }
}

void BM_Pratt_ParseCommonSyntaxErrors(benchmark::State& state) {
  BM_ParseCommonSyntaxErrors(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseCommonSyntaxErrors(benchmark::State& state) {
  BM_ParseCommonSyntaxErrors(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseCommonSyntaxErrors);
BENCHMARK(BM_Antlr_ParseCommonSyntaxErrors);

// -----------------------------------------------------------------------------
// Workload 7: Deep Left-Associative Arithmetic Chains with Syntax Error
// ("a + a + ... + ")
// -----------------------------------------------------------------------------
std::string BuildArithmeticChainSyntaxError(int length) {
  std::string expr = BuildArithmeticChain(length);
  absl::StrAppend(&expr, " +");
  return expr;
}

void BM_ParseArithmeticChainSyntaxError(benchmark::State& state,
                                        ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildArithmeticChainSyntaxError(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK(!ast.ok());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseArithmeticChainSyntaxError(benchmark::State& state) {
  BM_ParseArithmeticChainSyntaxError(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseArithmeticChainSyntaxError(benchmark::State& state) {
  BM_ParseArithmeticChainSyntaxError(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseArithmeticChainSyntaxError)->Arg(10)->Arg(50)->Arg(100);
BENCHMARK(BM_Antlr_ParseArithmeticChainSyntaxError)->Arg(10)->Arg(50)->Arg(100);

// -----------------------------------------------------------------------------
// Workload 8: Wide Logical Expression Chains with Syntax Error
// ("a || a || ... || ")
// -----------------------------------------------------------------------------
std::string BuildLogicalChainSyntaxError(int length) {
  std::string expr = BuildLogicalChain(length);
  absl::StrAppend(&expr, " ||");
  return expr;
}

void BM_ParseLogicalChainSyntaxError(benchmark::State& state,
                                     ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildLogicalChainSyntaxError(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK(!ast.ok());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseLogicalChainSyntaxError(benchmark::State& state) {
  BM_ParseLogicalChainSyntaxError(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseLogicalChainSyntaxError(benchmark::State& state) {
  BM_ParseLogicalChainSyntaxError(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseLogicalChainSyntaxError)->Arg(10)->Arg(50)->Arg(100);
BENCHMARK(BM_Antlr_ParseLogicalChainSyntaxError)->Arg(10)->Arg(50)->Arg(100);

// -----------------------------------------------------------------------------
// Workload 9: Deep Member Access Chains with Syntax Error ("a.f.f...f.")
// -----------------------------------------------------------------------------
std::string BuildMemberChainSyntaxError(int length) {
  std::string expr = BuildMemberChain(length);
  absl::StrAppend(&expr, ".");
  return expr;
}

void BM_ParseMemberChainSyntaxError(benchmark::State& state,
                                    ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildMemberChainSyntaxError(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK(!ast.ok());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseMemberChainSyntaxError(benchmark::State& state) {
  BM_ParseMemberChainSyntaxError(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseMemberChainSyntaxError(benchmark::State& state) {
  BM_ParseMemberChainSyntaxError(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseMemberChainSyntaxError)->Arg(10)->Arg(50)->Arg(100);
BENCHMARK(BM_Antlr_ParseMemberChainSyntaxError)->Arg(10)->Arg(50)->Arg(100);

// -----------------------------------------------------------------------------
// Workload 10: Deeply Nested Parentheses with Syntax Error ("(((((a")
// -----------------------------------------------------------------------------
std::string BuildNestedParenthesesSyntaxError(int depth) {
  std::string prefix(depth, '(');
  return absl::StrCat(prefix, "a");
}

void BM_ParseNestedParenthesesSyntaxError(benchmark::State& state,
                                          ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildNestedParenthesesSyntaxError(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK(!ast.ok());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseNestedParenthesesSyntaxError(benchmark::State& state) {
  BM_ParseNestedParenthesesSyntaxError(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseNestedParenthesesSyntaxError(benchmark::State& state) {
  BM_ParseNestedParenthesesSyntaxError(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseNestedParenthesesSyntaxError)->Arg(10)->Arg(50);
BENCHMARK(BM_Antlr_ParseNestedParenthesesSyntaxError)->Arg(10)->Arg(50);

// -----------------------------------------------------------------------------
// Workload 11: Repeated Syntax Errors ("f(*, *, *, ...)")
// -----------------------------------------------------------------------------
std::string BuildRepeatedSyntaxErrors(int length) {
  std::string expr = "f(*";
  for (int i = 1; i < length; ++i) {
    absl::StrAppend(&expr, ", *");
  }
  absl::StrAppend(&expr, ")");
  return expr;
}

void BM_ParseRepeatedSyntaxErrors(benchmark::State& state,
                                  ParserImplType type) {
  cel::ParserOptions options;
  auto parser = CreateParser(type, options);
  std::string expr = BuildRepeatedSyntaxErrors(state.range(0));

  for (auto _ : state) {
    auto source = cel::NewSource(expr);
    ABSL_DCHECK_OK(source.status());
    auto ast = parser->Parse(**source);
    ABSL_DCHECK(!ast.ok());
    benchmark::DoNotOptimize(ast);
  }
}

void BM_Pratt_ParseRepeatedSyntaxErrors(benchmark::State& state) {
  BM_ParseRepeatedSyntaxErrors(state, ParserImplType::kPratt);
}
void BM_Antlr_ParseRepeatedSyntaxErrors(benchmark::State& state) {
  BM_ParseRepeatedSyntaxErrors(state, ParserImplType::kAntlr);
}

BENCHMARK(BM_Pratt_ParseRepeatedSyntaxErrors)->Arg(10)->Arg(50)->Arg(100);
BENCHMARK(BM_Antlr_ParseRepeatedSyntaxErrors)->Arg(10)->Arg(50)->Arg(100);

}  // namespace
}  // namespace cel::parser_internal
