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

#include "parser/internal/pratt_parser.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/nullability.h"
#include "absl/cleanup/cleanup.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "common/ast.h"
#include "common/expr.h"
#include "common/source.h"
#include "internal/status_macros.h"
#include "parser/internal/ast_factory.h"  // IWYU pragma: keep
#include "parser/internal/pratt_parser_worker.h"
#include "parser/macro.h"
#include "parser/macro_registry.h"
#include "parser/options.h"
#include "parser/parser_interface.h"

namespace cel::parser_internal {

namespace {

std::string DisplayParserError(const cel::Source& source,
                               SourceLocation location,
                               std::string_view message) {
  int32_t display_column =
      location.column >= 0 ? location.column + 1 : location.column;
  return absl::StrCat(
      absl::StrFormat("ERROR: %s:%d:%d: %s", source.description(),
                      location.line, display_column, message),
      source.DisplayErrorLocation(location));
}

std::string FormatIssues(const cel::Source& source,
                         absl::Span<const cel::ParseIssue> issues) {
  return absl::StrJoin(
      issues, "\n", [&source](std::string* out, const cel::ParseIssue& issue) {
        absl::StrAppend(
            out, DisplayParserError(source, issue.location(), issue.message()));
      });
}

}  // namespace

absl::Status PrattParserBuilderImpl::AddMacro(const cel::Macro& macro) {
  for (const cel::Macro& existing_macro : macros_) {
    if (existing_macro.key() == macro.key()) {
      return absl::AlreadyExistsError(
          absl::StrCat("macro already exists: ", macro.key()));
    }
  }
  macros_.push_back(macro);
  return absl::OkStatus();
}

absl::Status PrattParserBuilderImpl::AddLibrary(cel::ParserLibrary library) {
  if (!library.id.empty()) {
    auto [it, inserted] = library_ids_.insert(library.id);
    if (!inserted) {
      return absl::AlreadyExistsError(
          absl::StrCat("parser library already exists: ", library.id));
    }
  }
  libraries_.push_back(std::move(library));
  return absl::OkStatus();
}

absl::Status PrattParserBuilderImpl::AddLibrarySubset(
    cel::ParserLibrarySubset subset) {
  if (subset.library_id.empty()) {
    return absl::InvalidArgumentError("subset must have a library id");
  }
  std::string library_id = subset.library_id;
  auto [it, inserted] =
      library_subsets_.insert({library_id, std::move(subset)});
  if (!inserted) {
    return absl::AlreadyExistsError(
        absl::StrCat("parser library subset already exists: ", library_id));
  }
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<cel::Parser>> PrattParserBuilderImpl::Build() {
  using std::swap;
  std::vector<cel::Macro> individual_macros;
  swap(individual_macros, macros_);
  absl::Cleanup cleanup([&] { swap(macros_, individual_macros); });

  cel::MacroRegistry macro_registry;

  for (const cel::ParserLibrary& library : libraries_) {
    CEL_RETURN_IF_ERROR(library.configure(*this));
    if (!library.id.empty()) {
      auto it = library_subsets_.find(library.id);
      if (it != library_subsets_.end()) {
        const cel::ParserLibrarySubset& subset = it->second;
        for (const cel::Macro& macro : macros_) {
          if (subset.should_include_macro(macro)) {
            CEL_RETURN_IF_ERROR(macro_registry.RegisterMacro(macro));
          }
        }
        macros_.clear();
        continue;
      }
    }

    CEL_RETURN_IF_ERROR(macro_registry.RegisterMacros(macros_));
    macros_.clear();
  }

  absl::flat_hash_set<std::string> library_ids(library_ids_);

  if (!options_.disable_standard_macros && !library_ids_.contains("stdlib")) {
    CEL_RETURN_IF_ERROR(macro_registry.RegisterMacros(Macro::AllMacros()));
    library_ids.insert("stdlib");
  }

  if (options_.enable_optional_syntax && !library_ids_.contains("optional")) {
    CEL_RETURN_IF_ERROR(macro_registry.RegisterMacro(cel::OptMapMacro()));
    CEL_RETURN_IF_ERROR(macro_registry.RegisterMacro(cel::OptFlatMapMacro()));
    library_ids.insert("optional");
  }

  CEL_RETURN_IF_ERROR(macro_registry.RegisterMacros(individual_macros));
  return std::make_unique<PrattParserImpl>(options_, std::move(macro_registry),
                                           std::move(library_ids));
}

template class PrattParserWorker<cel::Expr>;

absl::StatusOr<std::unique_ptr<cel::Ast>> PrattParserImpl::ParseImpl(
    const cel::Source& source,
    std::vector<cel::ParseIssue>* absl_nullable parse_issues) const {
  return PrattParseImpl(source, macro_registry_, options_, parse_issues);
}

absl::StatusOr<std::unique_ptr<cel::Source>> PrattParserImpl::PrepareSourceImpl(
    absl::string_view input, absl::string_view description) const {
  return cel::NewSource(
      input, std::string(description),
      cel::SourceOptions{.max_codepoint_size =
                             options_.expression_size_codepoint_limit});
}

absl::StatusOr<std::unique_ptr<cel::Ast>> PrattParseImpl(
    const cel::Source& source, const cel::MacroRegistry& registry,
    const ParserOptions& options, std::vector<cel::ParseIssue>* parse_issues) {
  if (source.content().size() > options.expression_size_codepoint_limit) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "expression size exceeds codepoint limit. input size: %zu, limit: %d",
        source.content().size(), options.expression_size_codepoint_limit));
  }
  std::vector<cel::ParseIssue> issues;
  AstFactory factory(&registry);
  PrattParserWorker<cel::Expr> worker(source, options, &issues, factory);
  Expr expr = worker.Parse();
  if (worker.is_recursion_limit_exceeded()) {
    return absl::CancelledError(
        absl::StrFormat("Expression recursion limit exceeded. limit: %d",
                        options.max_recursion_depth));
  }
  if (worker.has_errors()) {
    absl::c_stable_sort(
        issues, [](const cel::ParseIssue& lhs, const cel::ParseIssue& rhs) {
          if (lhs.location().line != rhs.location().line) {
            return lhs.location().line < rhs.location().line;
          }
          return lhs.location().column < rhs.location().column;
        });
    std::string err_msg = FormatIssues(source, issues);
    if (parse_issues != nullptr) {
      parse_issues->swap(issues);
    }
    return absl::InvalidArgumentError(err_msg);
  }

  cel::SourceInfo source_info;
  source_info.set_location(std::string(source.description()));
  for (const auto& [id, pos] : worker.GetNodePositions()) {
    source_info.mutable_positions().insert({id, pos});
  }
  source_info.mutable_line_offsets().reserve(source.line_offsets().size());
  for (int32_t offset : source.line_offsets()) {
    source_info.mutable_line_offsets().push_back(offset);
  }
  source_info.mutable_macro_calls() = worker.ReleaseMacroCalls();
  return std::make_unique<cel::Ast>(std::move(expr), std::move(source_info));
}

std::unique_ptr<cel::ParserBuilder> PrattParserImpl::ToBuilder() const {
  auto ins = std::make_unique<PrattParserBuilderImpl>(options_);
  ins->library_ids_ = library_ids_;
  ins->macros_ = macro_registry_.ListMacros();
  return ins;
}

}  // namespace cel::parser_internal
