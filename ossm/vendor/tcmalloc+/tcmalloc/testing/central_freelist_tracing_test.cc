// Copyright 2026 The TCMalloc Authors
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

#include <stddef.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/internal/spinlock.h"
#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_set.h"
#include "absl/types/span.h"
#include "tcmalloc/common.h"
#include "tcmalloc/internal/central_freelist_hooks.h"
#include "tcmalloc/internal/logging.h"
#include "tcmalloc/malloc_hook.h"

constexpr size_t kMaxTraceObjects =
    tcmalloc::tcmalloc_internal::kMaxObjectsToMove;

static absl::base_internal::SpinLock spinlock(
    absl::base_internal::SCHEDULE_KERNEL_ONLY);

static size_t remove_range_count ABSL_GUARDED_BY(spinlock) = 0;
static const void* remove_range_objects[kMaxTraceObjects] ABSL_GUARDED_BY(
    spinlock);

constexpr size_t kMaxNewObjects = 10000;
static size_t new_hook_count ABSL_GUARDED_BY(spinlock) = 0;
static const void* new_hook_objects[kMaxNewObjects] ABSL_GUARDED_BY(spinlock);

// Record multiple batches to handle different caching behaviors.
static void RecordRemoveRangeBatchHook(size_t size_class,
                                       absl::Span<void*> batch) {
  absl::base_internal::SpinLockHolder l(spinlock);

  if (remove_range_count + batch.size() <= kMaxTraceObjects) {
    for (void* ptr : batch) {
      remove_range_objects[remove_range_count++] = ptr;
    }
  }
}

// Record multiple allocations to increase the chance of finding a match.
static void RecordNewHook(const tcmalloc::MallocHook::NewInfo& info) {
  if (info.allocated_size > tcmalloc::tcmalloc_internal::kMaxSize) {
    return;
  }

  absl::base_internal::SpinLockHolder l(spinlock);
  if (new_hook_count < kMaxNewObjects) {
    new_hook_objects[new_hook_count++] = info.ptr;
  }
}

extern "C" void MallocHook_InitAtFirstAllocation_ForTesting() {
  TC_CHECK(tcmalloc::MallocHook::AddNewHook(RecordNewHook));
}

extern "C" void TCMalloc_CentralFreeList_InitAtFirstRemoveRange_Tracing() {
  TC_CHECK(tcmalloc::tcmalloc_internal::central_freelist_remove_range_hooks.Add(
      RecordRemoveRangeBatchHook));
}

namespace tcmalloc {
namespace {

TEST(CentralFreeListTracingTest, CalledEarly) {
  if (tcmalloc_internal::kSanitizerPresent) {
    GTEST_SKIP() << "Skipping under sanitizers";
  }

  // Verify that our first callback from RemoveRange corresponds to an size
  // class-ful object we returned via NewHook.

  // Google Test will certainly allocate before here, but guarantee that we
  // have.
  ::operator delete(::operator new(16));

  // Stop recording allocations.
  TC_CHECK(tcmalloc::MallocHook::RemoveNewHook(RecordNewHook));
  TC_CHECK(
      tcmalloc::tcmalloc_internal::central_freelist_remove_range_hooks.Remove(
          RecordRemoveRangeBatchHook));

  absl::flat_hash_set<const void*> cfl;
  cfl.reserve(kMaxTraceObjects);

  bool found = false;
  {
    absl::base_internal::SpinLockHolder l(spinlock);

    for (size_t i = 0; i < remove_range_count; ++i) {
      cfl.insert(remove_range_objects[i]);
    }

    for (size_t i = 0; i < new_hook_count; ++i) {
      if (cfl.contains(new_hook_objects[i])) {
        found = true;
        break;
      }
    }

    EXPECT_FALSE(cfl.empty());
    EXPECT_NE(new_hook_count, 0);
  }

  EXPECT_TRUE(found) << "None of the early allocations were found in the "
                        "central freelist batch";
}

}  // namespace
}  // namespace tcmalloc
