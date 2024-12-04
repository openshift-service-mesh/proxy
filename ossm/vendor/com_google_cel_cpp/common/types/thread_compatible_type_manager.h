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

// IWYU pragma: private

#ifndef THIRD_PARTY_CEL_CPP_COMMON_TYPES_THREAD_COMPATIBLE_TYPE_MANAGER_H_
#define THIRD_PARTY_CEL_CPP_COMMON_TYPES_THREAD_COMPATIBLE_TYPE_MANAGER_H_

#include <utility>

#include "absl/strings/string_view.h"
#include "common/memory.h"
#include "common/sized_input_view.h"
#include "common/type.h"
#include "common/type_manager.h"
#include "common/type_provider.h"
#include "common/types/type_cache.h"

namespace cel::common_internal {

class ThreadCompatibleTypeManager : public virtual TypeManager {
 public:
  explicit ThreadCompatibleTypeManager(MemoryManagerRef memory_manager,
                                       Shared<TypeProvider> type_provider)
      : memory_manager_(memory_manager),
        type_provider_(std::move(type_provider)) {}

  MemoryManagerRef GetMemoryManager() const final { return memory_manager_; }

 protected:
  TypeProvider& GetTypeProvider() const final { return *type_provider_; }

 private:
  ListType CreateListTypeImpl(TypeView element) final;

  MapType CreateMapTypeImpl(TypeView key, TypeView value) final;

  StructType CreateStructTypeImpl(absl::string_view name) final;

  OpaqueType CreateOpaqueTypeImpl(
      absl::string_view name, const SizedInputView<TypeView>& parameters) final;

  MemoryManagerRef memory_manager_;
  Shared<TypeProvider> type_provider_;
  ListTypeCacheMap list_types_;
  MapTypeCacheMap map_types_;
  StructTypeCacheMap struct_types_;
  OpaqueTypeCacheMap opaque_types_;
};

}  // namespace cel::common_internal

#endif  // THIRD_PARTY_CEL_CPP_COMMON_TYPES_THREAD_COMPATIBLE_TYPE_MANAGER_H_
