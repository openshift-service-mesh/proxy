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

#include "common/values/thread_safe_value_manager.h"

#include <utility>

#include "absl/synchronization/mutex.h"
#include "common/type.h"
#include "common/value.h"
#include "common/values/value_cache.h"

namespace cel::common_internal {

ListValue ThreadSafeValueManager::CreateZeroListValueImpl(ListTypeView type) {
  {
    absl::ReaderMutexLock lock(&list_values_mutex_);
    if (auto list_value = list_values_.find(type);
        list_value != list_values_.end()) {
      return list_value->second;
    }
  }
  ListValue list_value(
      GetMemoryManager().MakeShared<EmptyListValue>(ListType(type)));
  type = list_value.type();
  absl::WriterMutexLock lock(&list_values_mutex_);
  return list_values_.insert(std::pair{type, std::move(list_value)})
      .first->second;
}

MapValue ThreadSafeValueManager::CreateZeroMapValueImpl(MapTypeView type) {
  {
    absl::ReaderMutexLock lock(&map_values_mutex_);
    if (auto map_value = map_values_.find(type);
        map_value != map_values_.end()) {
      return map_value->second;
    }
  }
  MapValue map_value(
      GetMemoryManager().MakeShared<EmptyMapValue>(MapType(type)));
  type = map_value.type();
  absl::WriterMutexLock lock(&map_values_mutex_);
  return map_values_.insert(std::pair{type, std::move(map_value)})
      .first->second;
}

OptionalValue ThreadSafeValueManager::CreateZeroOptionalValueImpl(
    OptionalTypeView type) {
  {
    absl::ReaderMutexLock lock(&optional_values_mutex_);
    if (auto optional_value = optional_values_.find(type);
        optional_value != optional_values_.end()) {
      return optional_value->second;
    }
  }
  OptionalValue optional_value(
      GetMemoryManager().MakeShared<EmptyOptionalValue>(OptionalType(type)));
  type = optional_value.type();
  absl::WriterMutexLock lock(&optional_values_mutex_);
  return optional_values_.insert(std::pair{type, std::move(optional_value)})
      .first->second;
}

}  // namespace cel::common_internal
