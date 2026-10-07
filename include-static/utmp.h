#ifndef _RLIBC_UTMP_H
#define _RLIBC_UTMP_H 1

#include <bits/rlibc-features.h>
#include <sys/types.h>
#include <paths.h>

#define UT_LINESIZE 32
#define UT_NAMESIZE 32
#define UT_HOSTSIZE 256

struct lastlog {
  unsigned int ll_time;
  char ll_line[UT_LINESIZE];
  char ll_host[UT_HOSTSIZE];
};

struct exit_status {
  short int e_termination;
  short int e_exit;
};

struct utmp {
  short int ut_type;
  pid_t ut_pid;
  char ut_line[UT_LINESIZE];
  char ut_id[4];
  char ut_user[UT_NAMESIZE];
  char ut_host[UT_HOSTSIZE];
  struct exit_status ut_exit;
  int ut_session;
  struct {
    unsigned int tv_sec;
    int tv_usec;
  } ut_tv;
  int ut_addr_v6[4];
  char __glibc_reserved[20];
};

#define ut_name ut_user
#ifndef _NO_UT_TIME
# define ut_time ut_tv.tv_sec
#endif
#define ut_xtime ut_tv.tv_sec
#define ut_addr ut_addr_v6[0]

#define EMPTY 0
#define RUN_LVL 1
#define BOOT_TIME 2
#define NEW_TIME 3
#define OLD_TIME 4
#define INIT_PROCESS 5
#define LOGIN_PROCESS 6
#define USER_PROCESS 7
#define DEAD_PROCESS 8
#define ACCOUNTING 9

#define UT_UNKNOWN EMPTY

#define _HAVE_UT_TYPE 1
#define _HAVE_UT_PID 1
#define _HAVE_UT_ID 1
#define _HAVE_UT_TV 1
#define _HAVE_UT_HOST 1

#define UTMP_FILE _PATH_UTMP
#define UTMP_FILENAME _PATH_UTMP
#define WTMP_FILE _PATH_WTMP
#define WTMP_FILENAME _PATH_WTMP

#ifdef __cplusplus
extern "C" {
#endif
extern int login_tty (int __fd);
#include <bits/rlibc-utmpcalls.h>
#ifdef __RLIBC_USE_MISC
# include <bits/rlibc-utmpcalls-misc.h>
#endif
#ifdef __cplusplus
}
#endif

#endif
