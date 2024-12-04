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

#ifndef THIRD_PARTY_CEL_CPP_RUNTIME_MANAGED_VALUE_FACTORY_H_
#define THIRD_PARTY_CEL_CPP_RUNTIME_MANAGED_VALUE_FACTORY_H_

#include "base/memory.h"
#include "base/type_factory.h"
#include "base/type_manager.h"
#include "base/type_provider.h"
#include "base/value_factory.h"

namespace cel {

// A convenience class for managing objects associated with a ValueFactory.
class ManagedValueFactory {
 public:
  // type_provider and memory_manager must outlive the ManagedValueFactory.
  ManagedValueFactory(const TypeProvider& type_provider,
                      MemoryManagerRef memory_manager)
      : type_factory_(memory_manager),
        type_manager_(type_factory_, type_provider),
        value_factory_(type_manager_) {}

  // Move-only
  ManagedValueFactory(const ManagedValueFactory& other) = delete;
  ManagedValueFactory& operator=(const ManagedValueFactory& other) = delete;
  ManagedValueFactory(ManagedValueFactory&& other) = delete;
  ManagedValueFactory& operator=(ManagedValueFactory&& other) = delete;

  ValueFactory& get() { return value_factory_; }

 private:
  TypeFactory type_factory_;
  TypeManager type_manager_;
  ValueFactory value_factory_;
};

}  // namespace cel

#endif  // THIRD_PARTY_CEL_CPP_RUNTIME_MANAGED_VALUE_FACTORY_H_
