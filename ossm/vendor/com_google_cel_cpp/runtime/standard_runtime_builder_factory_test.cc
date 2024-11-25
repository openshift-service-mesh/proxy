// Copyright 2023 Google LLC
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

#include "runtime/standard_runtime_builder_factory.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "google/api/expr/v1alpha1/syntax.pb.h"
#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "base/handle.h"
#include "base/memory.h"
#include "base/type_factory.h"
#include "base/type_manager.h"
#include "base/value.h"
#include "base/value_factory.h"
#include "base/values/bool_value.h"
#include "extensions/bindings_ext.h"
#include "extensions/protobuf/memory_manager.h"
#include "extensions/protobuf/runtime_adapter.h"
#include "internal/no_destructor.h"
#include "internal/testing.h"
#include "parser/macro.h"
#include "parser/parser.h"
#include "runtime/activation.h"
#include "runtime/managed_value_factory.h"
#include "runtime/runtime.h"
#include "runtime/runtime_issue.h"
#include "runtime/runtime_options.h"
#include "google/protobuf/arena.h"

namespace cel {
namespace {

using ::cel::extensions::ProtobufRuntimeAdapter;
using ::cel::extensions::ProtoMemoryManagerRef;
using ::google::api::expr::v1alpha1::ParsedExpr;
using ::google::api::expr::parser::ParseWithMacros;
using testing::ElementsAre;
using testing::Truly;

struct EvaluateResultTestCase {
  std::string name;
  std::string expression;
  bool expected_result;
  std::function<absl::Status(ValueFactory&, Activation&)> activation_builder;
};

const std::vector<google::api::expr::parser::Macro>& GetMacros() {
  static internal::NoDestructor<std::vector<google::api::expr::parser::Macro>>
      macros([]() {
        std::vector<google::api::expr::parser::Macro> value;
        absl::c_copy(google::api::expr::parser::Macro::AllMacros(),
                     std::back_inserter(value));
        absl::c_copy(extensions::bindings_macros(), std::back_inserter(value));
        return value;
      }());
  return *macros;
}

class StandardRuntimeTest
    : public ::testing::TestWithParam<EvaluateResultTestCase> {};

TEST_P(StandardRuntimeTest, DefaultsRefCounted) {
  RuntimeOptions opts;
  const EvaluateResultTestCase& test_case = GetParam();
  MemoryManagerRef memory_manager = MemoryManagerRef::ReferenceCounting();

  ASSERT_OK_AND_ASSIGN(auto builder, CreateStandardRuntimeBuilder(opts));

  ASSERT_OK_AND_ASSIGN(auto runtime, std::move(builder).Build());

  ASSERT_OK_AND_ASSIGN(ParsedExpr expr,
                       ParseWithMacros(test_case.expression, GetMacros()));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Program> program,
                       ProtobufRuntimeAdapter::CreateProgram(*runtime, expr));

  TypeFactory type_factory(memory_manager);
  TypeManager type_manager(type_factory, runtime->GetTypeProvider());
  ValueFactory value_factory(type_manager);

  Activation activation;
  activation.InsertOrAssignValue("int_var", value_factory.CreateIntValue(42));

  ASSERT_OK_AND_ASSIGN(Handle<Value> result,
                       program->Evaluate(activation, value_factory));

  ASSERT_TRUE(result->Is<BoolValue>()) << result->DebugString();
  EXPECT_EQ(result->As<BoolValue>().NativeValue(), test_case.expected_result)
      << test_case.expression;
}

TEST_P(StandardRuntimeTest, DefaultsArena) {
  RuntimeOptions opts;
  const EvaluateResultTestCase& test_case = GetParam();
  google::protobuf::Arena arena;
  auto memory_manager = ProtoMemoryManagerRef(&arena);

  ASSERT_OK_AND_ASSIGN(auto builder, CreateStandardRuntimeBuilder(opts));

  ASSERT_OK_AND_ASSIGN(auto runtime, std::move(builder).Build());

  ASSERT_OK_AND_ASSIGN(ParsedExpr expr,
                       ParseWithMacros(test_case.expression, GetMacros()));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Program> program,
                       ProtobufRuntimeAdapter::CreateProgram(*runtime, expr));

  TypeFactory type_factory(memory_manager);
  TypeManager type_manager(type_factory, runtime->GetTypeProvider());
  ValueFactory value_factory(type_manager);

  Activation activation;
  if (test_case.activation_builder != nullptr) {
    ASSERT_OK(test_case.activation_builder(value_factory, activation));
  }

  ASSERT_OK_AND_ASSIGN(Handle<Value> result,
                       program->Evaluate(activation, value_factory));

  ASSERT_TRUE(result->Is<BoolValue>()) << result->DebugString();
  EXPECT_EQ(result->As<BoolValue>().NativeValue(), test_case.expected_result)
      << test_case.expression;
}

std::string TestCaseName(
    const testing::TestParamInfo<EvaluateResultTestCase>& info) {
  return info.param.name;
}

INSTANTIATE_TEST_SUITE_P(
    Basic, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        {"int_identifier", "int_var == 42", true,
         [](ValueFactory& value_factory, Activation& activation) {
           activation.InsertOrAssignValue("int_var",
                                          value_factory.CreateIntValue(42));
           return absl::OkStatus();
         }},
        {"logic_and_true", "true && 1 < 2", true},
        {"logic_and_false", "true && 1 > 2", false},
        {"logic_or_true", "false || 1 < 2", true},
        {"logic_or_false", "false && 1 > 2", false},
        {"ternary_true_cond", "(1 < 2 ? 'yes' : 'no') == 'yes'", true},
        {"ternary_false_cond", "(1 > 2 ? 'yes' : 'no') == 'no'", true},
        {"list_index", "['a', 'b', 'c', 'd'][1] == 'b'", true},
        // TODO(uncreated-issue/32): these depend on updating map creation to use
        // modern values.
        // {"map_index_bool", "{true: 1, false: 2}[false] == 2", true},
        // {"map_index_string", "{'abc': 123}['abc'] == 123", true},
        // {"map_index_int", "{1: 2, 2: 4}[2] == 4", true},
        // {"map_index_uint", "{1u: 1, 2u: 2}[1u] == 1", true},
        // {"map_index_coerced_double", "{1: 2, 2: 4}[2.0] == 4", true},
    }),
    TestCaseName);

INSTANTIATE_TEST_SUITE_P(
    Equality, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        {"eq_bool_bool_true", "false == false", true},
        {"eq_bool_bool_false", "false == true", false},
        {"eq_int_int_true", "-1 == -1", true},
        {"eq_int_int_false", "-1 == 1", false},
        {"eq_uint_uint_true", "2u == 2u", true},
        {"eq_uint_uint_false", "2u == 3u", false},
        {"eq_double_double_true", "2.4 == 2.4", true},
        {"eq_double_double_false", "2.4 == 3.3", false},
        {"eq_string_string_true", "'abc' == 'abc'", true},
        {"eq_string_string_false", "'abc' == 'def'", false},
        {"eq_bytes_bytes_true", "b'abc' == b'abc'", true},
        {"eq_bytes_bytes_false", "b'abc' == b'def'", false},
        {"eq_duration_duration_true", "duration('15m') == duration('15m')",
         true},
        {"eq_duration_duration_false", "duration('15m') == duration('1h')",
         false},
        {"eq_timestamp_timestamp_true",
         "timestamp('1970-01-01T00:02:00Z') == "
         "timestamp('1970-01-01T00:02:00Z')",
         true},
        {"eq_timestamp_timestamp_false",
         "timestamp('1970-01-01T00:02:00Z') == "
         "timestamp('2020-01-01T00:02:00Z')",
         false},
        {"eq_null_null_true", "null == null", true},
        {"eq_list_list_true", "[1, 2, 3] == [1, 2, 3]", true},
        {"eq_list_list_false", "[1, 2, 3] == [1, 2, 3, 4]", false},
        // TODO(uncreated-issue/32): these depend on updating map creation to use
        // modern values.
        // {"eq_map_map_true", "{1: 2, 2: 4} == {1: 2, 2: 4}", true},
        // {"eq_map_map_false", "{1: 2, 2: 4} == {1: 2, 2: 5}", false},

        {"neq_bool_bool_true", "false != false", false},
        {"neq_bool_bool_false", "false != true", true},
        {"neq_int_int_true", "-1 != -1", false},
        {"neq_int_int_false", "-1 != 1", true},
        {"neq_uint_uint_true", "2u != 2u", false},
        {"neq_uint_uint_false", "2u != 3u", true},
        {"neq_double_double_true", "2.4 != 2.4", false},
        {"neq_double_double_false", "2.4 != 3.3", true},
        {"neq_string_string_true", "'abc' != 'abc'", false},
        {"neq_string_string_false", "'abc' != 'def'", true},
        {"neq_bytes_bytes_true", "b'abc' != b'abc'", false},
        {"neq_bytes_bytes_false", "b'abc' != b'def'", true},
        {"neq_duration_duration_true", "duration('15m') != duration('15m')",
         false},
        {"neq_duration_duration_false", "duration('15m') != duration('1h')",
         true},
        {"neq_timestamp_timestamp_true",
         "timestamp('1970-01-01T00:02:00Z') != "
         "timestamp('1970-01-01T00:02:00Z')",
         false},
        {"neq_timestamp_timestamp_false",
         "timestamp('1970-01-01T00:02:00Z') != "
         "timestamp('2020-01-01T00:02:00Z')",
         true},
        {"neq_null_null_true", "null != null", false},
        {"neq_list_list_true", "[1, 2, 3] != [1, 2, 3]", false},
        {"neq_list_list_false", "[1, 2, 3] != [1, 2, 3, 4]", true}
        // TODO(uncreated-issue/32): these depend on updating map creation to use
        // modern values.
        // {"neq_map_map_true", "{1: 2, 2: 4} != {1: 2, 2: 4}", false },
        // {"neq_map_map_false", "{1: 2, 2: 4} != {1: 2, 2: 5}", true }
    }),
    TestCaseName);

INSTANTIATE_TEST_SUITE_P(
    ArithmeticFunctions, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        {"lt_int_int_true", "-1 < 2", true},
        {"lt_int_int_false", "2 < -1", false},
        {"lt_double_double_true", "-1.1 < 2.2", true},
        {"lt_double_double_false", "2.2 < -1.1", false},
        {"lt_uint_uint_true", "1u < 2u", true},
        {"lt_uint_uint_false", "2u < 1u", false},
        {"lt_string_string_true", "'abc' < 'def'", true},
        {"lt_string_string_false", "'def' < 'abc'", false},
        {"lt_duration_duration_true", "duration('1s') < duration('2s')", true},
        {"lt_duration_duration_false", "duration('2s') < duration('1s')",
         false},
        {"lt_timestamp_timestamp_true", "timestamp(1) < timestamp(2)", true},
        {"lt_timestamp_timestamp_false", "timestamp(2) < timestamp(1)", false},

        {"gt_int_int_false", "-1 > 2", false},
        {"gt_int_int_true", "2 > -1", true},
        {"gt_double_double_false", "-1.1 > 2.2", false},
        {"gt_double_double_true", "2.2 > -1.1", true},
        {"gt_uint_uint_false", "1u > 2u", false},
        {"gt_uint_uint_true", "2u > 1u", true},
        {"gt_string_string_false", "'abc' > 'def'", false},
        {"gt_string_string_true", "'def' > 'abc'", true},
        {"gt_duration_duration_false", "duration('1s') > duration('2s')",
         false},
        {"gt_duration_duration_true", "duration('2s') > duration('1s')", true},
        {"gt_timestamp_timestamp_false", "timestamp(1) > timestamp(2)", false},
        {"gt_timestamp_timestamp_true", "timestamp(2) > timestamp(1)", true},

        {"le_int_int_true", "-1 <= -1", true},
        {"le_int_int_false", "2 <= -1", false},
        {"le_double_double_true", "-1.1 <= -1.1", true},
        {"le_double_double_false", "2.2 <= -1.1", false},
        {"le_uint_uint_true", "1u <= 1u", true},
        {"le_uint_uint_false", "2u <= 1u", false},
        {"le_string_string_true", "'abc' <= 'abc'", true},
        {"le_string_string_false", "'def' <= 'abc'", false},
        {"le_duration_duration_true", "duration('1s') <= duration('1s')", true},
        {"le_duration_duration_false", "duration('2s') <= duration('1s')",
         false},
        {"le_timestamp_timestamp_true", "timestamp(1) <= timestamp(1)", true},
        {"le_timestamp_timestamp_false", "timestamp(2) <= timestamp(1)", false},

        {"ge_int_int_false", "-1 >= 2", false},
        {"ge_int_int_true", "2 >= 2", true},
        {"ge_double_double_false", "-1.1 >= 2.2", false},
        {"ge_double_double_true", "2.2 >= 2.2", true},
        {"ge_uint_uint_false", "1u >= 2u", false},
        {"ge_uint_uint_true", "2u >= 2u", true},
        {"ge_string_string_false", "'abc' >= 'def'", false},
        {"ge_string_string_true", "'abc' >= 'abc'", true},
        {"ge_duration_duration_false", "duration('1s') >= duration('2s')",
         false},
        {"ge_duration_duration_true", "duration('1s') >= duration('1s')", true},
        {"ge_timestamp_timestamp_false", "timestamp(1) >= timestamp(2)", false},
        {"ge_timestamp_timestamp_true", "timestamp(1) >= timestamp(1)", true},

        {"sum_int_int", "1 + 2 == 3", true},
        {"sum_uint_uint", "3u + 4u == 7", true},
        {"sum_double_double", "1.0 + 2.5 == 3.5", true},
        {"sum_duration_duration",
         "duration('2m') + duration('30s') == duration('150s')", true},
        {"sum_time_duration",
         "timestamp(0) + duration('2m') == timestamp('1970-01-01T00:02:00Z')",
         true},

        {"difference_int_int", "1 - 2 == -1", true},
        {"difference_uint_uint", "4u - 3u == 1u", true},
        {"difference_double_double", "1.0 - 2.5 == -1.5", true},
        {"difference_duration_duration",
         "duration('5m') - duration('45s') == duration('4m15s')", true},
        {"difference_time_time",
         "timestamp(10) - timestamp(0) == duration('10s')", true},
        {"difference_time_duration",
         "timestamp(0) - duration('2m') == timestamp('1969-12-31T23:58:00Z')",
         true},

        {"multiplication_int_int", "2 * 3 == 6", true},
        {"multiplication_uint_uint", "2u * 3u == 6u", true},
        {"multiplication_double_double", "2.5 * 3.0 == 7.5", true},

        {"division_int_int", "6 / 3 == 2", true},
        {"division_uint_uint", "8u / 4u == 2u", true},
        {"division_double_double", "1.0 / 0.0 == double('inf')", true},

        {"modulo_int_int", "6 % 4 == 2", true},
        {"modulo_uint_uint", "8u % 5u == 3u", true},
    }),
    TestCaseName);

INSTANTIATE_TEST_SUITE_P(
    Macros, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        {"map", "[1, 2, 3, 4].map(x, x * x)[3] == 16", true},
        {"filter", "[1, 2, 3, 4].filter(x, x < 4).size() == 3", true},
        {"exists", "[1, 2, 3, 4].exists(x, x < 4)", true},
        {"all", "[1, 2, 3, 4].all(x, x < 5)", true}}),
    TestCaseName);

INSTANTIATE_TEST_SUITE_P(
    StringFunctions, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        {"string_contains", "'tacocat'.contains('acoca')", true},
        {"string_contains_global", "contains('tacocat', 'dog')", false},
        {"string_ends_with", "'abcdefg'.endsWith('efg')", true},
        {"string_ends_with_global", "endsWith('abcdefg', 'fgh')", false},
        {"string_starts_with", "'abcdefg'.startsWith('abc')", true},
        {"string_starts_with_global", "startsWith('abcd', 'bcd')", false},
        {"string_size", "'Hello World! 😀'.size() == 14", true},
        {"string_size_global", "size('Hello world!') == 12", true},
        {"bytes_size", "b'0123'.size() == 4", true},
        {"bytes_size_global", "size(b'😀') == 4", true}}),
    TestCaseName);

INSTANTIATE_TEST_SUITE_P(
    RegExFunctions, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        {"matches_string_re",
         "'127.0.0.1'.matches(r'127\\.\\d+\\.\\d+\\.\\d+')", true},
        {"matches_string_re_global",
         "matches('192.168.0.1', r'127\\.\\d+\\.\\d+\\.\\d+')", false}}),
    TestCaseName);

INSTANTIATE_TEST_SUITE_P(
    TimeFunctions, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        {"timestamp_get_full_year",
         "timestamp('2001-02-03T04:05:06.007Z').getFullYear() == 2001", true},
        {"timestamp_get_date",
         "timestamp('2001-02-03T04:05:06.007Z').getDate() == 3", true},
        {"timestamp_get_hours",
         "timestamp('2001-02-03T04:05:06.007Z').getHours() == 4", true},
        {"timestamp_get_minutes",
         "timestamp('2001-02-03T04:05:06.007Z').getMinutes() == 5", true},
        {"timestamp_get_seconds",
         "timestamp('2001-02-03T04:05:06.007Z').getSeconds() == 6", true},
        {"timestamp_get_milliseconds",
         "timestamp('2001-02-03T04:05:06.007Z').getMilliseconds() == 7", true},
        // Zero based indexing
        {"timestamp_get_month",
         "timestamp('2001-02-03T04:05:06.007Z').getMonth() == 1", true},
        {"timestamp_get_day_of_year",
         "timestamp('2001-02-03T04:05:06.007Z').getDayOfYear() == 33", true},
        {"timestamp_get_day_of_month",
         "timestamp('2001-02-03T04:05:06.007Z').getDayOfMonth() == 2", true},
        {"timestamp_get_day_of_week",
         "timestamp('2001-02-03T04:05:06.007Z').getDayOfWeek() == 6", true},
        {"duration_get_hours", "duration('10h20m30s40ms').getHours() == 10",
         true},
        {"duration_get_minutes",
         "duration('10h20m30s40ms').getMinutes() == 20 + 600", true},
        {"duration_get_seconds",
         "duration('10h20m30s40ms').getSeconds() == 30 + 20 * 60 + 10 * 60 * "
         "60",
         true},
        {"duration_get_milliseconds",
         "duration('10h20m30s40ms').getMilliseconds() == 40", true},
    }),
    TestCaseName);

INSTANTIATE_TEST_SUITE_P(
    TypeConversionFunctions, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        {"string_timestamp", "string(timestamp(1)) == '1970-01-01T00:00:01Z'",
         true},
        {"string_duration", "string(duration('10m30s')) == '630s'", true},
        {"string_int", "string(-1) == '-1'", true},
        {"string_uint", "string(1u) == '1'", true},
        {"string_double", "string(double('inf')) == 'inf'", true},
        {"string_bytes", R"(string(b'\xF0\x9F\x98\x80') == '😀')", true},
        {"string_string", "string('hello!') == 'hello!'", true},
        {"bytes_bytes", "bytes(b'123') == b'123'", true},
        {"bytes_string", "bytes('😀') == b'\xF0\x9F\x98\x80'", true},
        {"timestamp", "timestamp(1) == timestamp('1970-01-01T00:00:01Z')",
         true},
        {"duration", "duration('10h') == duration('600m')", true},
        {"double_string", "double('1.0') == 1.0", true},
        {"double_string_nan", "double('nan') != double('nan')", true},
        {"double_int", "double(1) == 1.0", true},
        {"double_uint", "double(1u) == 1.0", true},
        {"double_double", "double(1.0) == 1.0", true},
        {"uint_string", "uint('1') == 1u", true},
        {"uint_int", "uint(1) == 1u", true},
        {"uint_uint", "uint(1u) == 1u", true},
        {"uint_double", "uint(1.1) == 1u", true},
        {"int_string", "int('-1') == -1", true},
        {"int_int", "int(-1) == -1", true},
        {"int_uint", "int(1u) == 1", true},
        {"int_double", "int(-1.1) == -1", true},
        {"int_timestamp", "int(timestamp('1969-12-31T23:30:00Z')) == -1800",
         true},
    }),
    TestCaseName);

INSTANTIATE_TEST_SUITE_P(
    ContainerFunctions, StandardRuntimeTest,
    testing::ValuesIn(std::vector<EvaluateResultTestCase>{
        // Containers
        // TODO(uncreated-issue/32): these depend on updating map creation to use
        // modern values.
        // {"map_size", "{'abc': 1, 'def': 2}.size() == 2", true}
        // {"map_in", "'abc' in {'abc': 1, 'def': 2}", true}
        // {"map_in_numeric", "1.0 in {1u: 1, 2u: 2}.size() == 2", true}
        {"list_size", "[1, 2, 3, 4].size() == 4", true},
        {"list_size_global", "size([1, 2, 3]) == 3", true},
        {"list_concat", "[1, 2] + [3, 4] == [1, 2, 3, 4]", true},
        {"list_in", "'a' in ['a', 'b', 'c', 'd']", true},
        {"list_in_numeric", "3u in [1.1, 2.3, 3.0, 4.4]", true}}),
    TestCaseName);

TEST(StandardRuntimeTest, RuntimeIssueSupport) {
  RuntimeOptions options;
  options.fail_on_warnings = false;

  google::protobuf::Arena arena;
  auto memory_manager = ProtoMemoryManagerRef(&arena);

  ASSERT_OK_AND_ASSIGN(auto builder, CreateStandardRuntimeBuilder(options));

  ASSERT_OK_AND_ASSIGN(auto runtime, std::move(builder).Build());

  {
    ASSERT_OK_AND_ASSIGN(
        ParsedExpr expr,
        ParseWithMacros("unregistered_function(1)", GetMacros()));

    std::vector<RuntimeIssue> issues;
    ASSERT_OK_AND_ASSIGN(
        std::unique_ptr<Program> program,
        ProtobufRuntimeAdapter::CreateProgram(*runtime, expr, {&issues}));

    EXPECT_THAT(issues, ElementsAre(Truly([](const RuntimeIssue& issue) {
                  return issue.severity() == RuntimeIssue::Severity::kWarning &&
                         issue.error_code() ==
                             RuntimeIssue::ErrorCode::kNoMatchingOverload;
                })));
  }

  {
    ASSERT_OK_AND_ASSIGN(
        ParsedExpr expr,
        ParseWithMacros("unregistered_function(1) || unregistered_function(2)",
                        GetMacros()));

    std::vector<RuntimeIssue> issues;
    ASSERT_OK_AND_ASSIGN(
        std::unique_ptr<Program> program,
        ProtobufRuntimeAdapter::CreateProgram(*runtime, expr, {&issues}));

    EXPECT_THAT(
        issues,
        ElementsAre(
            Truly([](const RuntimeIssue& issue) {
              return issue.severity() == RuntimeIssue::Severity::kWarning &&
                     issue.error_code() ==
                         RuntimeIssue::ErrorCode::kNoMatchingOverload;
            }),
            Truly([](const RuntimeIssue& issue) {
              return issue.severity() == RuntimeIssue::Severity::kWarning &&
                     issue.error_code() ==
                         RuntimeIssue::ErrorCode::kNoMatchingOverload;
            })));
  }

  {
    ASSERT_OK_AND_ASSIGN(
        ParsedExpr expr,
        ParseWithMacros(
            "unregistered_function(1) || unregistered_function(2) || true",
            GetMacros()));

    std::vector<RuntimeIssue> issues;
    ASSERT_OK_AND_ASSIGN(
        std::unique_ptr<Program> program,
        ProtobufRuntimeAdapter::CreateProgram(*runtime, expr, {&issues}));

    EXPECT_THAT(
        issues,
        ElementsAre(
            Truly([](const RuntimeIssue& issue) {
              return issue.severity() == RuntimeIssue::Severity::kWarning &&
                     issue.error_code() ==
                         RuntimeIssue::ErrorCode::kNoMatchingOverload;
            }),
            Truly([](const RuntimeIssue& issue) {
              return issue.severity() == RuntimeIssue::Severity::kWarning &&
                     issue.error_code() ==
                         RuntimeIssue::ErrorCode::kNoMatchingOverload;
            })));

    ManagedValueFactory value_factory(program->GetTypeProvider(),
                                      memory_manager);
    Activation activation;

    ASSERT_OK_AND_ASSIGN(auto result,
                         program->Evaluate(activation, value_factory.get()));
    EXPECT_TRUE(result->Is<BoolValue>() &&
                result->As<BoolValue>().NativeValue());
  }
}

}  // namespace
}  // namespace cel
