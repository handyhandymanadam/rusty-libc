#ifndef _RLIBC_UTMPX_H
#define _RLIBC_UTMPX_H 1

#include <bits/rlibc-features.h>
#include <sys/types.h>
#ifdef __RLIBC_USE_GNU
# include <paths.h>
# define _PATH_UTMPX _PATH_UTMP
# define _PATH_WTMPX _PATH_WTMP
#endif

#define __UT_LINESIZE 32
#define __UT_NAMESIZE 32
#define __UT_HOSTSIZE 256

struct __exit_status {
#ifdef __RLIBC_USE_GNU
  short int e_termination;
  short int e_exit;
#else
  short int __e_termination;
  short int __e_exit;
#endif
};

struct utmpx {
  short int ut_type;
  pid_t ut_pid;
  char ut_line[__UT_LINESIZE];
  char ut_id[4];
  char ut_user[__UT_NAMESIZE];
  char ut_host[__UT_HOSTSIZE];
  struct __exit_status ut_exit;
  int ut_session;
  struct {
    unsigned int tv_sec;
    int tv_usec;
  } ut_tv;
  int ut_addr_v6[4];
  char __glibc_reserved[20];
};

#define EMPTY 0
#ifdef __RLIBC_USE_GNU
# define RUN_LVL 1
#endif
#define BOOT_TIME 2
#define NEW_TIME 3
#define OLD_TIME 4
#define INIT_PROCESS 5
#define LOGIN_PROCESS 6
#define USER_PROCESS 7
#define DEAD_PROCESS 8
#ifdef __RLIBC_USE_GNU
# define ACCOUNTING 9
#endif

#ifdef __RLIBC_USE_GNU
# define UTMPX_FILE _PATH_UTMPX
# define UTMPX_FILENAME _PATH_UTMPX
# define WTMPX_FILE _PATH_WTMPX
# define WTMPX_FILENAME _PATH_WTMPX
struct utmp;
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <bits/rlibc-utmpxcalls.h>
#ifdef __RLIBC_USE_GNU
# include <bits/rlibc-utmpxcalls-misc.h>
#endif
#ifdef __cplusplus
}
#endif

#endif
