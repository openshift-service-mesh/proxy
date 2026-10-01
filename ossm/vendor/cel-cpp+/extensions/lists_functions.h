// Copyright 2024 Google LLC
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

#ifndef THIRD_PARTY_CEL_CPP_EXTENSIONS_LISTS_FUNCTIONS_H_
#define THIRD_PARTY_CEL_CPP_EXTENSIONS_LISTS_FUNCTIONS_H_

#include <cstdint>

#include "absl/status/status.h"
#include "checker/type_checker_builder.h"
#include "compiler/compiler.h"
#include "parser/macro_registry.h"
#include "parser/options.h"
#include "runtime/function_registry.h"
#include "runtime/runtime_options.h"

namespace cel::extensions {

constexpr int kListsExtensionLatestVersion = 2;

struct ListsExtensionOptions {
  int version = kListsExtensionLatestVersion;

  // Maximum size allowed for lists.range().
  // Setting a tighter limit (e.g. 100) will restrict the max size further.
  // A standard limit of 1,000,000 applies if a tighter limit isn't
  // configured.
  int64_t max_range_size = 1000000;
};

using ListsFunctionsOptions = ListsExtensionOptions;

// Register implementations for list extension functions.
//
// === Since version 0 ===
// <list(T)>.slice(start: int, end: int) -> list(T)
//
// === Since version 1 ===
// <list(dyn)>.flatten() -> list(dyn)
// <list(dyn)>.flatten(limit: int) -> list(dyn)
//
// === Since version 2 ===
// lists.range(n: int) -> list(int)
//
// <list(T)>.distinct() -> list(T)
//
// <list(T)>.reverse() -> list(T)
//
// <list(T)>.sort() -> list(T)
//
absl::Status RegisterListsFunctions(
    FunctionRegistry& registry, const RuntimeOptions& options,
    const ListsExtensionOptions& extension_options = {});

inline absl::Status RegisterListsFunctions(FunctionRegistry& registry,
                                           const RuntimeOptions& options,
                                           int version) {
  ListsExtensionOptions extension_options;
  extension_options.version = version;
  return RegisterListsFunctions(registry, options, extension_options);
}

// Register list macros.
//
// === Since version 2 ===
//
// <list(T)>.sortBy(<element name>, <element key expression>)
absl::Status RegisterListsMacros(MacroRegistry& registry,
                                 const ParserOptions& options,
                                 int version = kListsExtensionLatestVersion);

// Type check declarations for the lists extension library.
// Provides decls for the following functions:
//
// === Since version 0 ===
// <list(T)>.slice(start: int, end: int) -> list(T)
//
// === Since version 1 ===
// <list(dyn)>.flatten() -> list(dyn)
// <list(dyn)>.flatten(limit: int) -> list(dyn)
//
// === Since version 2 ===
// lists.range(n: int) -> list(int)
//
// <list(T)>.distinct() -> list(T)
//
// <list(T)>.reverse() -> list(T)
//
// <list(T_)>.sort() -> list(T_) where T_ is partially orderable
CheckerLibrary ListsCheckerLibrary(
    const ListsExtensionOptions& extension_options = {});

inline CheckerLibrary ListsCheckerLibrary(int version) {
  ListsExtensionOptions extension_options;
  extension_options.version = version;
  return ListsCheckerLibrary(extension_options);
}

// Provides decls for the following functions:
//
// === Since version 0 ===
// <list(T)>.slice(start: int, end: int) -> list(T)
//
// === Since version 1 ===
// <list(dyn)>.flatten() -> list(dyn)
// <list(dyn)>.flatten(limit: int) -> list(dyn)
//
// === Since version 2 ===
// lists.range(n: int) -> list(int)
//
// <list(T)>.distinct() -> list(T)
//
// <list(T)>.reverse() -> list(T)
//
// <list(T_)>.sort() -> list(T_) where T_ is partially orderable
CompilerLibrary ListsCompilerLibrary(
    const ListsExtensionOptions& extension_options = {});

inline CompilerLibrary ListsCompilerLibrary(int version) {
  ListsExtensionOptions extension_options;
  extension_options.version = version;
  return ListsCompilerLibrary(extension_options);
}

}  // namespace cel::extensions

#endif  // THIRD_PARTY_CEL_CPP_EXTENSIONS_LISTS_FUNCTIONS_H_
