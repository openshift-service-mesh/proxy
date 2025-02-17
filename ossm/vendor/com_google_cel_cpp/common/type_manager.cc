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

#include "common/type_manager.h"

#include <utility>

#include "common/memory.h"
#include "common/type_provider.h"
#include "common/types/thread_compatible_type_manager.h"
#include "common/types/thread_safe_type_manager.h"

namespace cel {

Shared<TypeManager> NewThreadCompatibleTypeManager(
    MemoryManagerRef memory_manager, Shared<TypeProvider> type_provider) {
  return memory_manager
      .MakeShared<common_internal::ThreadCompatibleTypeManager>(
          memory_manager, std::move(type_provider));
}

Shared<TypeManager> NewThreadSafeTypeManager(
    MemoryManagerRef memory_manager, Shared<TypeProvider> type_provider) {
  return memory_manager.MakeShared<common_internal::ThreadSafeTypeManager>(
      memory_manager, std::move(type_provider));
}

}  // namespace cel
