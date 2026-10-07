#ifndef _AIO_H
#define _AIO_H 1

#include <stddef.h>
#include <sys/types.h>
#include <bits/types/struct_sigevent.h>
#include <bits/types/struct_timespec.h>

#if defined _GNU_SOURCE
# define __RLIBC_AIO_GNU 1
#endif
#if defined _GNU_SOURCE || defined _LARGEFILE64_SOURCE
# define __RLIBC_AIO_LFS64 1
#endif
#if defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64
# define __RLIBC_AIO_FOFF64 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct aiocb {
  int aio_fildes;
  int aio_lio_opcode;
  int aio_reqprio;
  volatile void *aio_buf;
  size_t aio_nbytes;
  struct sigevent aio_sigevent;

  struct aiocb *__next_prio;
  int __abs_prio;
  int __policy;
  int __error_code;
  ssize_t __return_value;

  off_t aio_offset;
  char __glibc_reserved[32];
};

#ifdef __RLIBC_AIO_LFS64
struct aiocb64 {
  int aio_fildes;
  int aio_lio_opcode;
  int aio_reqprio;
  volatile void *aio_buf;
  size_t aio_nbytes;
  struct sigevent aio_sigevent;

  struct aiocb *__next_prio;
  int __abs_prio;
  int __policy;
  int __error_code;
  ssize_t __return_value;

  off64_t aio_offset;
  char __glibc_reserved[32];
};
#endif

#ifdef __RLIBC_AIO_GNU
struct aioinit {
  int aio_threads;
  int aio_num;
  int aio_locks;
  int aio_usedba;
  int aio_debug;
  int aio_numusers;
  int aio_idle_time;
  int aio_reserved;
};
#endif

enum {
  AIO_CANCELED,
#define AIO_CANCELED AIO_CANCELED
  AIO_NOTCANCELED,
#define AIO_NOTCANCELED AIO_NOTCANCELED
  AIO_ALLDONE
#define AIO_ALLDONE AIO_ALLDONE
};

enum {
  LIO_READ,
#define LIO_READ LIO_READ
  LIO_WRITE,
#define LIO_WRITE LIO_WRITE
  LIO_NOP
#define LIO_NOP LIO_NOP
};

enum {
  LIO_WAIT,
#define LIO_WAIT LIO_WAIT
  LIO_NOWAIT
#define LIO_NOWAIT LIO_NOWAIT
};

#ifdef __RLIBC_AIO_FOFF64
extern int aio_read (struct aiocb *__aiocbp) __asm__ ("aio_read64");
extern int aio_write (struct aiocb *__aiocbp) __asm__ ("aio_write64");
extern int lio_listio (int __mode, struct aiocb *const __list[], int __nent, struct sigevent *__sig) __asm__ ("lio_listio64");
extern int aio_error (const struct aiocb *__aiocbp) __asm__ ("aio_error64");
extern ssize_t aio_return (struct aiocb *__aiocbp) __asm__ ("aio_return64");
extern int aio_cancel (int __fildes, struct aiocb *__aiocbp) __asm__ ("aio_cancel64");
extern int aio_suspend (const struct aiocb *const __list[], int __nent, const struct timespec *__timeout) __asm__ ("aio_suspend64");
extern int aio_fsync (int __operation, struct aiocb *__aiocbp) __asm__ ("aio_fsync64");
#else
# include <bits/rlibc-aio-calls.h>
#endif

#ifdef __RLIBC_AIO_LFS64
# include <bits/rlibc-aio-64.h>
#endif

#ifdef __RLIBC_AIO_GNU
# include <bits/rlibc-aio-gnu.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
