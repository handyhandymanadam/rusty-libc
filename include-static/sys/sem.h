#ifndef _SYS_SEM_H
#define _SYS_SEM_H 1

#include <stddef.h>
#include <sys/types.h>
#include <sys/ipc.h>

#if defined _GNU_SOURCE
# define __RLIBC_SEM_GNU 1
#endif
#if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)
# define __RLIBC_SEM_MISC 1
#endif
#ifdef __RLIBC_SEM_GNU
# include <bits/types/struct_timespec.h>
#endif

struct semid_ds {
  struct ipc_perm sem_perm;
  time_t sem_otime;
  unsigned long int __sem_otime_high;
  time_t sem_ctime;
  unsigned long int __sem_ctime_high;
  unsigned long int sem_nsems;
  unsigned long int __glibc_reserved3;
  unsigned long int __glibc_reserved4;
};

#define SEM_UNDO 0x1000

#define GETPID 11
#define GETVAL 12
#define GETALL 13
#define GETNCNT 14
#define GETZCNT 15
#define SETVAL 16
#define SETALL 17

#define _SEM_SEMUN_UNDEFINED 1

#ifdef __RLIBC_SEM_MISC
# define SEM_STAT 18
# define SEM_INFO 19
# define SEM_STAT_ANY 20
struct seminfo {
  int semmap;
  int semmni;
  int semmns;
  int semmnu;
  int semmsl;
  int semopm;
  int semume;
  int semusz;
  int semvmx;
  int semaem;
};
#endif

struct sembuf {
  unsigned short int sem_num;
  short int sem_op;
  short int sem_flg;
};

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-ipc-sem.h>
#ifdef __RLIBC_SEM_GNU
# include <bits/rlibc-ipc-semgnu.h>
#endif
#ifdef __cplusplus
}
#endif

#endif
