#include <event2/event-config.h>

#ifdef __APPLE__
#include <event2/util.h>
#endif

#ifdef EVENT__HAVE_PTHREADS
#include <pthread.h>
#endif

#ifdef EVENT__HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdio.h>

// For the Bazel build, the sizeof macros in event-config_*.h were entered by
// hand instead of by CMake. Test that the values are correct.
int TestSizeof() {
  int pass = 1;

#define TEST_SIZEOF(macro, type)                                    \
  if ((size_t)(macro) != sizeof(type)) {                            \
    fprintf(stderr, "FAIL: %s[=%zu] != sizeof(%s)[=%zu]\n", #macro, \
            (size_t)macro, #type, sizeof(type));                    \
    pass = 0;                                                       \
  }

#ifdef EVENT__HAVE_PTHREADS
  TEST_SIZEOF(EVENT__SIZEOF_PTHREAD_T, pthread_t);
#endif
  TEST_SIZEOF(EVENT__SIZEOF_INT, int);
  TEST_SIZEOF(EVENT__SIZEOF_LONG, long);
  TEST_SIZEOF(EVENT__SIZEOF_LONG_LONG, long long);
#ifdef EVENT__SIZEOF_OFF_T
  TEST_SIZEOF(EVENT__SIZEOF_OFF_T, off_t);
#endif
  TEST_SIZEOF(EVENT__SIZEOF_SHORT, short);
  TEST_SIZEOF(EVENT__SIZEOF_SIZE_T, size_t);
  TEST_SIZEOF(EVENT__SIZEOF_VOID_P, void*);

#undef TEST_SIZEOF

  return pass;
}

int main() {
  int pass = 1;

  if (!TestSizeof()) {
    pass = 0;
  }

#ifdef __APPLE__
  // The TCP fallback cannot create Unix datagram socket pairs.
  evutil_socket_t sockets[2];
  if (evutil_socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) {
    perror("FAIL: evutil_socketpair(AF_UNIX, SOCK_DGRAM)");
    pass = 0;
  } else {
    evutil_closesocket(sockets[0]);
    evutil_closesocket(sockets[1]);
  }
#endif

  if (pass) {
    printf("PASS\n");
    return 0;
  } else {
    printf("FAIL\n");
    return 1;
  }
}
