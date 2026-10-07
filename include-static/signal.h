#ifndef _RLIBC_SIGNAL_H
#define _RLIBC_SIGNAL_H 1

#include <stddef.h>

#if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)
# define __RLIBC_SIG_MISC 1
#endif
#if defined _GNU_SOURCE || (defined _XOPEN_SOURCE && _XOPEN_SOURCE >= 500)
# define __RLIBC_SIG_XOPEN_EXT 1
#endif
#if defined __RLIBC_SIG_MISC || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200809L) \
    || (defined _XOPEN_SOURCE && _XOPEN_SOURCE >= 700)
# define __RLIBC_SIG_2K8 1
#endif
#if defined _GNU_SOURCE
# define __RLIBC_SIG_GNU 1
#endif
#if !defined __STRICT_ANSI__ || defined _POSIX_SOURCE || defined _POSIX_C_SOURCE || defined _XOPEN_SOURCE \
    || defined __RLIBC_SIG_MISC
# define __RLIBC_SIG_POSIX 1
#endif

#ifndef __sig_atomic_t_defined
# define __sig_atomic_t_defined 1
typedef int sig_atomic_t;
#endif

typedef void (*__sighandler_t) (int);
#define SIG_ERR ((__sighandler_t) -1)
#define SIG_DFL ((__sighandler_t) 0)
#define SIG_IGN ((__sighandler_t) 1)
#if defined __RLIBC_SIG_XOPEN_EXT
# define SIG_HOLD ((__sighandler_t) 2)
#endif

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGIOT SIGABRT
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCLD SIGCHLD
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGPOLL 29
#define SIGIO SIGPOLL
#define SIGPWR 30
#define SIGSYS 31
#define __SIGRTMIN 32
#define __SIGRTMAX 64
#define _NSIG (__SIGRTMAX + 1)
#ifdef __RLIBC_SIG_MISC
# define NSIG _NSIG
#endif

#ifdef __RLIBC_SIG_POSIX
# include <bits/types/sigset_t.h>
# ifndef _SIGSET_NWORDS
#  define _SIGSET_NWORDS (1024 / (8 * sizeof (unsigned long int)))
# endif
# ifndef __pid_t_defined
#  define __pid_t_defined 1
typedef int pid_t;
# endif
# ifndef __uid_t_defined
#  define __uid_t_defined 1
typedef unsigned int uid_t;
# endif
# ifndef __clock_t_defined
#  define __clock_t_defined 1
typedef long clock_t;
# endif
# include <bits/types/struct_timespec.h>
# include <bits/types/siginfo_t.h>
# include <bits/types/struct_sigevent.h>

enum {
  SI_ASYNCNL = -60,
  SI_DETHREAD = -7,
  SI_TKILL,
  SI_SIGIO,
  SI_ASYNCIO,
  SI_MESGQ,
  SI_TIMER,
  SI_QUEUE,
  SI_USER,
  SI_KERNEL = 0x80
# define SI_ASYNCNL SI_ASYNCNL
# define SI_DETHREAD SI_DETHREAD
# define SI_TKILL SI_TKILL
# define SI_SIGIO SI_SIGIO
# define SI_ASYNCIO SI_ASYNCIO
# define SI_MESGQ SI_MESGQ
# define SI_TIMER SI_TIMER
# define SI_QUEUE SI_QUEUE
# define SI_USER SI_USER
# define SI_KERNEL SI_KERNEL
};

# if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_2K8
enum {
  ILL_ILLOPC = 1,
#  define ILL_ILLOPC ILL_ILLOPC
  ILL_ILLOPN,
#  define ILL_ILLOPN ILL_ILLOPN
  ILL_ILLADR,
#  define ILL_ILLADR ILL_ILLADR
  ILL_ILLTRP,
#  define ILL_ILLTRP ILL_ILLTRP
  ILL_PRVOPC,
#  define ILL_PRVOPC ILL_PRVOPC
  ILL_PRVREG,
#  define ILL_PRVREG ILL_PRVREG
  ILL_COPROC,
#  define ILL_COPROC ILL_COPROC
  ILL_BADSTK,
#  define ILL_BADSTK ILL_BADSTK
  ILL_BADIADDR
#  define ILL_BADIADDR ILL_BADIADDR
};
enum {
  FPE_INTDIV = 1,
#  define FPE_INTDIV FPE_INTDIV
  FPE_INTOVF,
#  define FPE_INTOVF FPE_INTOVF
  FPE_FLTDIV,
#  define FPE_FLTDIV FPE_FLTDIV
  FPE_FLTOVF,
#  define FPE_FLTOVF FPE_FLTOVF
  FPE_FLTUND,
#  define FPE_FLTUND FPE_FLTUND
  FPE_FLTRES,
#  define FPE_FLTRES FPE_FLTRES
  FPE_FLTINV,
#  define FPE_FLTINV FPE_FLTINV
  FPE_FLTSUB,
#  define FPE_FLTSUB FPE_FLTSUB
  FPE_FLTUNK = 14,
#  define FPE_FLTUNK FPE_FLTUNK
  FPE_CONDTRAP
#  define FPE_CONDTRAP FPE_CONDTRAP
};
enum {
  SEGV_MAPERR = 1,
#  define SEGV_MAPERR SEGV_MAPERR
  SEGV_ACCERR,
#  define SEGV_ACCERR SEGV_ACCERR
  SEGV_BNDERR,
#  define SEGV_BNDERR SEGV_BNDERR
  SEGV_PKUERR,
#  define SEGV_PKUERR SEGV_PKUERR
  SEGV_ACCADI,
#  define SEGV_ACCADI SEGV_ACCADI
  SEGV_ADIDERR,
#  define SEGV_ADIDERR SEGV_ADIDERR
  SEGV_ADIPERR,
#  define SEGV_ADIPERR SEGV_ADIPERR
  SEGV_MTEAERR,
#  define SEGV_MTEAERR SEGV_MTEAERR
  SEGV_MTESERR,
#  define SEGV_MTESERR SEGV_MTESERR
  SEGV_CPERR
#  define SEGV_CPERR SEGV_CPERR
};
enum {
  BUS_ADRALN = 1,
#  define BUS_ADRALN BUS_ADRALN
  BUS_ADRERR,
#  define BUS_ADRERR BUS_ADRERR
  BUS_OBJERR,
#  define BUS_OBJERR BUS_OBJERR
  BUS_MCEERR_AR,
#  define BUS_MCEERR_AR BUS_MCEERR_AR
  BUS_MCEERR_AO
#  define BUS_MCEERR_AO BUS_MCEERR_AO
};
enum {
  CLD_EXITED = 1,
#  define CLD_EXITED CLD_EXITED
  CLD_KILLED,
#  define CLD_KILLED CLD_KILLED
  CLD_DUMPED,
#  define CLD_DUMPED CLD_DUMPED
  CLD_TRAPPED,
#  define CLD_TRAPPED CLD_TRAPPED
  CLD_STOPPED,
#  define CLD_STOPPED CLD_STOPPED
  CLD_CONTINUED
#  define CLD_CONTINUED CLD_CONTINUED
};
enum {
  POLL_IN = 1,
#  define POLL_IN POLL_IN
  POLL_OUT,
#  define POLL_OUT POLL_OUT
  POLL_MSG,
#  define POLL_MSG POLL_MSG
  POLL_ERR,
#  define POLL_ERR POLL_ERR
  POLL_PRI,
#  define POLL_PRI POLL_PRI
  POLL_HUP
#  define POLL_HUP POLL_HUP
};
# endif
# ifdef __RLIBC_SIG_XOPEN_EXT
enum {
  TRAP_BRKPT = 1,
#  define TRAP_BRKPT TRAP_BRKPT
  TRAP_TRACE,
#  define TRAP_TRACE TRAP_TRACE
  TRAP_BRANCH,
#  define TRAP_BRANCH TRAP_BRANCH
  TRAP_HWBKPT,
#  define TRAP_HWBKPT TRAP_HWBKPT
  TRAP_UNK,
#  define TRAP_UNK TRAP_UNK
  TRAP_PERF
#  define TRAP_PERF TRAP_PERF
};
# endif
# ifdef __RLIBC_SIG_GNU
enum {
  SYS_SECCOMP = 1,
#  define SYS_SECCOMP SYS_SECCOMP
  SYS_USER_DISPATCH
#  define SYS_USER_DISPATCH SYS_USER_DISPATCH
};
# endif

# ifdef __RLIBC_SIG_MISC
#  include <bits/types/__sigval_t.h>
typedef __sigval_t sigval_t;
# endif

# ifdef __RLIBC_SIG_GNU
typedef __sighandler_t sighandler_t;
# endif
# ifdef __RLIBC_SIG_MISC
typedef __sighandler_t sig_t;
#  define sigmask(sig) ((int)(1u << ((sig) - 1)))
# endif

struct sigaction {
  union {
    __sighandler_t sa_handler;
    void (*sa_sigaction) (int, siginfo_t *, void *);
  } __sigaction_handler;
# define sa_handler __sigaction_handler.sa_handler
# define sa_sigaction __sigaction_handler.sa_sigaction
  __sigset_t sa_mask;
  int sa_flags;
  void (*sa_restorer) (void);
};
# define SA_NOCLDSTOP 1
# define SA_NOCLDWAIT 2
# define SA_SIGINFO 4
# if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_MISC
#  define SA_ONSTACK 0x08000000
# endif
# if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_2K8
#  define SA_RESTART 0x10000000
#  define SA_NODEFER 0x40000000
#  define SA_RESETHAND 0x80000000
# endif
# ifdef __RLIBC_SIG_MISC
#  define SA_INTERRUPT 0x20000000
#  define SA_NOMASK SA_NODEFER
#  define SA_ONESHOT SA_RESETHAND
#  define SA_STACK SA_ONSTACK
# endif
# define SIG_BLOCK 0
# define SIG_UNBLOCK 1
# define SIG_SETMASK 2

# if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_2K8
#  include <sys/ucontext.h>
# endif
# if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_MISC
#  include <bits/types/stack_t.h>
#  define MINSIGSTKSZ 2048
#  define SIGSTKSZ 8192
#  if defined _GNU_SOURCE || defined _DYNAMIC_STACK_SIZE_SOURCE
#   include <unistd.h>
#   undef SIGSTKSZ
#   define SIGSTKSZ sysconf (_SC_SIGSTKSZ)
#   undef MINSIGSTKSZ
#   define MINSIGSTKSZ SIGSTKSZ
#  endif
enum {
  SS_ONSTACK = 1,
#  define SS_ONSTACK SS_ONSTACK
  SS_DISABLE
#  define SS_DISABLE SS_DISABLE
};
# endif
# if defined __RLIBC_SIG_MISC || (defined __RLIBC_SIG_XOPEN_EXT && !defined __RLIBC_SIG_2K8)
#  include <bits/types/struct_sigstack.h>
# endif
# ifdef __RLIBC_SIG_MISC
#  include <bits/sigcontext.h>
# endif
#endif

extern int raise (int __sig);
#ifdef __RLIBC_SIG_MISC
extern __sighandler_t signal (int __sig, __sighandler_t __handler);
#else
extern __sighandler_t signal (int __sig, __sighandler_t __handler) __asm__ ("__sysv_signal");
#endif
extern __sighandler_t __sysv_signal (int __sig, __sighandler_t __handler);

#ifdef __RLIBC_SIG_POSIX
# include <bits/rlibc-sigcalls-posix.h>
# if defined __RLIBC_SIG_MISC || defined __RLIBC_SIG_XOPEN_EXT
#  include <bits/rlibc-sigcalls-misc.h>
# endif
# ifdef __RLIBC_SIG_MISC
#  include <bits/rlibc-sigcalls-miscx.h>
# endif
# ifdef __RLIBC_SIG_2K8
#  include <bits/rlibc-sigcalls-k8.h>
# endif
# ifdef __RLIBC_SIG_XOPEN_EXT
#  include <bits/rlibc-sigcalls-xopen.h>
extern int sigpause (int __sig) __asm__ ("__xpg_sigpause");
# endif
# if defined __RLIBC_SIG_XOPEN_EXT && !defined __RLIBC_SIG_2K8
#  include <bits/rlibc-sigcalls-bsdsig.h>
# endif
# ifdef __RLIBC_SIG_GNU
#  include <bits/rlibc-sigcalls-gnu.h>
# endif
extern int pthread_sigmask (int __how, const sigset_t *__restrict __newmask, sigset_t *__restrict __oldmask);
extern int pthread_kill (unsigned long int __threadid, int __signo);
# ifdef __RLIBC_SIG_GNU
extern int pthread_sigqueue (unsigned long int __threadid, int __signo, const union sigval __value);
# endif
#endif

extern int __libc_current_sigrtmin (void);
extern int __libc_current_sigrtmax (void);
#define SIGRTMIN (__libc_current_sigrtmin ())
#define SIGRTMAX (__libc_current_sigrtmax ())

#endif
