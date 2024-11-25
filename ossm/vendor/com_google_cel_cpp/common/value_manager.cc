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

#include "common/value_manager.h"

#include <utility>

#include "common/memory.h"
#include "common/value_provider.h"
#include "common/values/thread_compatible_value_manager.h"
#include "common/values/thread_safe_value_manager.h"

namespace cel {

Shared<ValueManager> NewThreadCompatibleValueManager(
    MemoryManagerRef memory_manager, Shared<ValueProvider> value_provider) {
  return memory_manager
      .MakeShared<common_internal::ThreadCompatibleValueManager>(
          memory_manager, std::move(value_provider));
}

Shared<ValueManager> NewThreadSafeValueManager(
    MemoryManagerRef memory_manager, Shared<ValueProvider> value_provider) {
  return memory_manager.MakeShared<common_internal::ThreadSafeValueManager>(
      memory_manager, std::move(value_provider));
}

}  // namespace cel
