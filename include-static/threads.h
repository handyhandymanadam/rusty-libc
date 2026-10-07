#ifndef _RLIBC_THREADS_H
#define _RLIBC_THREADS_H 1

#include <stddef.h>
#include <time.h>
#include <bits/pthreadtypes.h>
#include <bits/types/struct_timespec.h>

#if (!defined __STDC_VERSION__ || __STDC_VERSION__ <= 201710L || !defined __GNUC__ || __GNUC__ < 13) && !defined __cplusplus
# define thread_local _Thread_local
#endif

#define ONCE_FLAG_INIT { 0 }
#define TSS_DTOR_ITERATIONS 4

typedef struct { int __data; } once_flag;
typedef unsigned int tss_t;
typedef void (*tss_dtor_t) (void *);
typedef unsigned long int thrd_t;
typedef int (*thrd_start_t) (void *);

enum {
  thrd_success = 0,
  thrd_busy = 1,
  thrd_error = 2,
  thrd_nomem = 3,
  thrd_timedout = 4
};

enum {
  mtx_plain = 0,
  mtx_recursive = 1,
  mtx_timed = 2
};

typedef union {
  char __size[__SIZEOF_PTHREAD_MUTEX_T];
  long int __align;
} mtx_t;

typedef union {
  char __size[__SIZEOF_PTHREAD_COND_T];
  long long int __align;
} cnd_t;

#ifdef __cplusplus
extern "C" {
#endif

#include <bits/rlibc-threadscalls.h>

#ifdef __cplusplus
}
#endif

#endif
