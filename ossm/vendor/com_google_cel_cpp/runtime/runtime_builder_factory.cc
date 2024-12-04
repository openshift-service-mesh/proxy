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

#include "runtime/runtime_builder_factory.h"

#include <memory>
#include <utility>

#include "runtime/internal/runtime_impl.h"
#include "runtime/runtime_builder.h"
#include "runtime/runtime_options.h"

namespace cel {

RuntimeBuilder CreateRuntimeBuilder(const RuntimeOptions& options) {
  // TODO(uncreated-issue/57): and internal API for adding extensions that need to
  // downcast to the runtime impl.
  // TODO(uncreated-issue/56): add API for attaching an issue listener (replacing the
  // vector<status> overloads).
  auto mutable_runtime =
      std::make_unique<runtime_internal::RuntimeImpl>(options);
  mutable_runtime->expr_builder().set_container(options.container);

  auto& type_registry = mutable_runtime->type_registry();
  auto& function_registry = mutable_runtime->function_registry();

  return RuntimeBuilder(type_registry, function_registry,
                        std::move(mutable_runtime));
}

}  // namespace cel
