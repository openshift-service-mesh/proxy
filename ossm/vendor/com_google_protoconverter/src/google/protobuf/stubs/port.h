/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GOOGLE_PROTOBUF_STUBS_PORT_H_
#define GOOGLE_PROTOBUF_STUBS_PORT_H_

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "google/protobuf/stubs/platform_macros.h"

#undef PROTOBUF_LITTLE_ENDIAN
#ifdef _WIN32
  // Assuming windows is always little-endian.
  // TODO(xiaofeng): The PROTOBUF_LITTLE_ENDIAN is not only used for
  // optimization but also for correctness. We should define an
  // different macro to test the big-endian code path in coded_stream.
  #if !defined(PROTOBUF_DISABLE_LITTLE_ENDIAN_OPT_FOR_TEST)
    #define PROTOBUF_LITTLE_ENDIAN 1
  #endif
#if defined(_MSC_VER) && _MSC_VER >= 1300 && !defined(__INTEL_COMPILER)
// If MSVC has "/RTCc" set, it will complain about truncating casts at
// runtime.  This file contains some intentional truncating casts.
#pragma runtime_checks("c", off)
#endif
#else
#if (defined(__APPLE__) || defined(__NEWLIB__))
#include <machine/endian.h>  // __BYTE_ORDER
#elif defined(__FreeBSD__)
#include <sys/endian.h>  // __BYTE_ORDER
#elif (defined(sun) || defined(__sun)) && (defined(__SVR4) || defined(__svr4__))
#include <sys/isa_defs.h>  // __BYTE_ORDER
#elif defined(_AIX) || defined(__TOS_AIX__)
#include <sys/machine.h>  // BYTE_ORDER
#elif defined(__QNX__)
#include <sys/param.h>  // BYTE_ORDER
#else
#include <endian.h>  // __BYTE_ORDER
#endif
#if ((defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)) ||   \
     (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) || \
     (defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN)) &&      \
    !defined(PROTOBUF_DISABLE_LITTLE_ENDIAN_OPT_FOR_TEST)
#define PROTOBUF_LITTLE_ENDIAN 1
#endif
#endif

// These #includes are for the byte swap functions declared later on.
#ifdef _MSC_VER
#include <stdlib.h>  // NOLINT(build/include)
#include <intrin.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#elif defined(__linux__) || defined(__ANDROID__) || defined(__CYGWIN__)
#include <byteswap.h>  // IWYU pragma: export
#endif

// Legacy: some users reference these (internal-only) macros even though we
// don't need them any more.
#if defined(_MSC_VER) && defined(PROTOBUF_USE_DLLS)
  #ifdef LIBPROTOBUF_EXPORTS
    #define LIBPROTOBUF_EXPORT __declspec(dllexport)
  #else
    #define LIBPROTOBUF_EXPORT __declspec(dllimport)
  #endif
  #ifdef LIBPROTOC_EXPORTS
    #define LIBPROTOC_EXPORT   __declspec(dllexport)
  #else
    #define LIBPROTOC_EXPORT   __declspec(dllimport)
  #endif
#else
  #define LIBPROTOBUF_EXPORT
  #define LIBPROTOC_EXPORT
#endif

#define PROTOBUF_RUNTIME_DEPRECATED(message) [[deprecated]] (message)
#define GOOGLE_PROTOBUF_RUNTIME_DEPRECATED(message) [[deprecated]] (message)

// ===================================================================
// from google3/base/port.h

#if (defined(__GXX_EXPERIMENTAL_CXX0X__) || __cplusplus >= 201103L || \
     (defined(_MSC_VER) && _MSC_VER >= 1900))
// Define this to 1 if the code is compiled in C++11 mode; leave it
// undefined otherwise.  Do NOT define it to 0 -- that causes
// '#ifdef LANG_CXX11' to behave differently from '#if LANG_CXX11'.
#define LANG_CXX11 1
#else
#error "Protobuf requires at least C++11."
#endif

namespace google {
namespace protobuf {

typedef unsigned int uint;

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

static const int32 kint32max = 0x7FFFFFFF;
static const int32 kint32min = -kint32max - 1;
static const int64 kint64max = int64_t{0x7FFFFFFFFFFFFFFF};
static const int64 kint64min = -kint64max - 1;
static const uint32 kuint32max = 0xFFFFFFFFu;
static const uint64 kuint64max = uint64_t{0xFFFFFFFFFFFFFFFFu};

inline uint16_t GOOGLE_UNALIGNED_LOAD16(const void *p) {
  uint16_t t;
  memcpy(&t, p, sizeof t);
  return t;
}

inline uint32_t GOOGLE_UNALIGNED_LOAD32(const void *p) {
  uint32_t t;
  memcpy(&t, p, sizeof t);
  return t;
}

inline uint64_t GOOGLE_UNALIGNED_LOAD64(const void *p) {
  uint64_t t;
  memcpy(&t, p, sizeof t);
  return t;
}

inline void GOOGLE_UNALIGNED_STORE16(void *p, uint16_t v) {
  memcpy(p, &v, sizeof v);
}

inline void GOOGLE_UNALIGNED_STORE32(void *p, uint32_t v) {
  memcpy(p, &v, sizeof v);
}

inline void GOOGLE_UNALIGNED_STORE64(void *p, uint64_t v) {
  memcpy(p, &v, sizeof v);
}

#if defined(GOOGLE_PROTOBUF_OS_NACL) \
    || (defined(__ANDROID__) && defined(__clang__) \
        && (__clang_major__ == 3 && __clang_minor__ == 8) \
        && (__clang_patchlevel__ < 275480))
# define GOOGLE_PROTOBUF_USE_PORTABLE_LOG2
#endif

// The following guarantees declaration of the byte swap functions.
#ifdef _MSC_VER
#define bswap_16(x) _byteswap_ushort(x)
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)

#elif defined(__APPLE__)
// Mac OS X / Darwin features
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#elif !defined(__linux__) && !defined(__ANDROID__) && !defined(__CYGWIN__)

#ifndef bswap_16
static inline uint16_t bswap_16(uint16_t x) {
  return static_cast<uint16_t>(((x & 0xFF) << 8) | ((x & 0xFF00) >> 8));
}
#define bswap_16(x) bswap_16(x)
#endif

#ifndef bswap_32
static inline uint32_t bswap_32(uint32_t x) {
  return (((x & 0xFF) << 24) |
          ((x & 0xFF00) << 8) |
          ((x & 0xFF0000) >> 8) |
          ((x & 0xFF000000) >> 24));
}
#define bswap_32(x) bswap_32(x)
#endif

#ifndef bswap_64
static inline uint64_t bswap_64(uint64_t x) {
  return (((x & uint64_t{0xFFu}) << 56) | ((x & uint64_t{0xFF00u}) << 40) |
          ((x & uint64_t{0xFF0000u}) << 24) |
          ((x & uint64_t{0xFF000000u}) << 8) |
          ((x & uint64_t{0xFF00000000u}) >> 8) |
          ((x & uint64_t{0xFF0000000000u}) >> 24) |
          ((x & uint64_t{0xFF000000000000u}) >> 40) |
          ((x & uint64_t{0xFF00000000000000u}) >> 56));
}
#define bswap_64(x) bswap_64(x)
#endif

#endif

// ===================================================================
// from google3/util/endian/endian.h
uint32_t ghtonl(uint32_t x);

class BigEndian {
 public:
#ifdef PROTOBUF_LITTLE_ENDIAN

  static uint16_t FromHost16(uint16_t x) { return bswap_16(x); }
  static uint16_t ToHost16(uint16_t x) { return bswap_16(x); }

  static uint32_t FromHost32(uint32_t x) { return bswap_32(x); }
  static uint32_t ToHost32(uint32_t x) { return bswap_32(x); }

  static uint64_t FromHost64(uint64_t x) { return bswap_64(x); }
  static uint64_t ToHost64(uint64_t x) { return bswap_64(x); }

  static bool IsLittleEndian() { return true; }

#else

  static uint16_t FromHost16(uint16_t x) { return x; }
  static uint16_t ToHost16(uint16_t x) { return x; }

  static uint32_t FromHost32(uint32_t x) { return x; }
  static uint32_t ToHost32(uint32_t x) { return x; }

  static uint64_t FromHost64(uint64_t x) { return x; }
  static uint64_t ToHost64(uint64_t x) { return x; }

  static bool IsLittleEndian() { return false; }

#endif /* ENDIAN */

  // Functions to do unaligned loads and stores in big-endian order.
  static uint16_t Load16(const void *p) {
    return ToHost16(GOOGLE_UNALIGNED_LOAD16(p));
  }

  static void Store16(void *p, uint16_t v) {
    GOOGLE_UNALIGNED_STORE16(p, FromHost16(v));
  }

  static uint32_t Load32(const void *p) {
    return ToHost32(GOOGLE_UNALIGNED_LOAD32(p));
  }

  static void Store32(void *p, uint32_t v) {
    GOOGLE_UNALIGNED_STORE32(p, FromHost32(v));
  }

  static uint64_t Load64(const void *p) {
    return ToHost64(GOOGLE_UNALIGNED_LOAD64(p));
  }

  static void Store64(void *p, uint64_t v) {
    GOOGLE_UNALIGNED_STORE64(p, FromHost64(v));
  }
};

}  // namespace protobuf
}  // namespace google

#endif  // GOOGLE_PROTOBUF_STUBS_PORT_H_
