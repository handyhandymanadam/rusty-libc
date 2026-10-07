#ifndef _RLIBC_SEMAPHORE_H
#define _RLIBC_SEMAPHORE_H 1

#include <stddef.h>
#include <bits/pthreadtypes.h>
#include <bits/types/struct_timespec.h>
#include <bits/types/clockid_t.h>

#define SEM_VALUE_MAX 2147483647
#define SEM_FAILED ((sem_t *) 0)

#ifndef __have_sem_t
# define __have_sem_t 1
typedef union {
  char __size[__SIZEOF_SEM_T];
  long int __align;
} sem_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-semcalls.h>
#ifdef __cplusplus
}
#endif

#endif
