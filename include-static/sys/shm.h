#ifndef _SYS_SHM_H
#define _SYS_SHM_H 1

#include <stddef.h>
#include <sys/types.h>
#include <sys/ipc.h>

#if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)
# define __RLIBC_SHM_MISC 1
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern int __getpagesize (void) __attribute__ ((__const__));
#ifdef __cplusplus
}
#endif
#define SHMLBA (__getpagesize ())

#define SHM_R 0400
#define SHM_W 0200

#define SHM_RDONLY 010000
#define SHM_RND 020000
#define SHM_REMAP 040000
#define SHM_EXEC 0100000

#define SHM_LOCK 11
#define SHM_UNLOCK 12

typedef unsigned long int shmatt_t;

struct shmid_ds {
  struct ipc_perm shm_perm;
  size_t shm_segsz;
  time_t shm_atime;
  time_t shm_dtime;
  time_t shm_ctime;
  pid_t shm_cpid;
  pid_t shm_lpid;
  shmatt_t shm_nattch;
  unsigned long int __glibc_reserved5;
  unsigned long int __glibc_reserved6;
};

#ifdef __RLIBC_SHM_MISC
# define SHM_STAT 13
# define SHM_INFO 14
# define SHM_STAT_ANY 15

# define SHM_DEST 01000
# define SHM_LOCKED 02000
# define SHM_HUGETLB 04000
# define SHM_NORESERVE 010000

# define SHM_HUGE_SHIFT 26
# define SHM_HUGE_MASK 0x3f
# define SHM_HUGE_16KB (14 << SHM_HUGE_SHIFT)
# define SHM_HUGE_64KB (16 << SHM_HUGE_SHIFT)
# define SHM_HUGE_512KB (19 << SHM_HUGE_SHIFT)
# define SHM_HUGE_1MB (20 << SHM_HUGE_SHIFT)
# define SHM_HUGE_2MB (21 << SHM_HUGE_SHIFT)
# define SHM_HUGE_8MB (23 << SHM_HUGE_SHIFT)
# define SHM_HUGE_16MB (24 << SHM_HUGE_SHIFT)
# define SHM_HUGE_32MB (25 << SHM_HUGE_SHIFT)
# define SHM_HUGE_256MB (28 << SHM_HUGE_SHIFT)
# define SHM_HUGE_512MB (29 << SHM_HUGE_SHIFT)
# define SHM_HUGE_1GB (30 << SHM_HUGE_SHIFT)
# define SHM_HUGE_2GB (31 << SHM_HUGE_SHIFT)
# define SHM_HUGE_16GB (34U << SHM_HUGE_SHIFT)

struct shminfo {
  unsigned long int shmmax;
  unsigned long int shmmin;
  unsigned long int shmmni;
  unsigned long int shmseg;
  unsigned long int shmall;
  unsigned long int __glibc_reserved1;
  unsigned long int __glibc_reserved2;
  unsigned long int __glibc_reserved3;
  unsigned long int __glibc_reserved4;
};

struct shm_info {
  int used_ids;
  unsigned long int shm_tot;
  unsigned long int shm_rss;
  unsigned long int shm_swp;
  unsigned long int swap_attempts;
  unsigned long int swap_successes;
};
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-ipc-shm.h>
#ifdef __cplusplus
}
#endif

#endif
