use crate::model::*;

pub static HDR: Header = Header {
    path: "signal.h",
    items: &[
        Item::Guard { name: "_RLIBC_SIGNAL_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_SIG_MISC", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE || (defined _XOPEN_SOURCE && _XOPEN_SOURCE >= 500)", items: &[
                    Item::Consts(&[
                        ("__RLIBC_SIG_XOPEN_EXT", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if defined __RLIBC_SIG_MISC || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200809L) \
    || (defined _XOPEN_SOURCE && _XOPEN_SOURCE >= 700)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_SIG_2K8", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE", items: &[
                    Item::Consts(&[
                        ("__RLIBC_SIG_GNU", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if !defined __STRICT_ANSI__ || defined _POSIX_SOURCE || defined _POSIX_C_SOURCE || defined _XOPEN_SOURCE \
    || defined __RLIBC_SIG_MISC"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_SIG_POSIX", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __sig_atomic_t_defined", items: &[
                    Item::Consts(&[
                        ("__sig_atomic_t_defined", V::Dec(1)),
                    ]),
                    Item::Typedef("int", "sig_atomic_t"),
                ] },
            ], ""),
            Item::Blank,
            Item::Decl("typedef void (*__sighandler_t) (int);"),
            Item::Consts(&[
                ("SIG_ERR", V::Txt("((__sighandler_t) -1)")),
                ("SIG_DFL", V::Txt("((__sighandler_t) 0)")),
                ("SIG_IGN", V::Txt("((__sighandler_t) 1)")),
            ]),
            Item::Gate(&[
                Branch { head: "if defined __RLIBC_SIG_XOPEN_EXT", items: &[
                    Item::Consts(&[
                        ("SIG_HOLD", V::Txt("((__sighandler_t) 2)")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Consts(&[
                ("SIGHUP", V::Dec(1)),
                ("SIGINT", V::Dec(2)),
                ("SIGQUIT", V::Dec(3)),
                ("SIGILL", V::Dec(4)),
                ("SIGTRAP", V::Dec(5)),
                ("SIGABRT", V::Dec(6)),
                ("SIGIOT", V::Txt("SIGABRT")),
                ("SIGBUS", V::Dec(7)),
                ("SIGFPE", V::Dec(8)),
                ("SIGKILL", V::Dec(9)),
                ("SIGUSR1", V::Dec(10)),
                ("SIGSEGV", V::Dec(11)),
                ("SIGUSR2", V::Dec(12)),
                ("SIGPIPE", V::Dec(13)),
                ("SIGALRM", V::Dec(14)),
                ("SIGTERM", V::Dec(15)),
                ("SIGSTKFLT", V::Dec(16)),
                ("SIGCHLD", V::Dec(17)),
                ("SIGCLD", V::Txt("SIGCHLD")),
                ("SIGCONT", V::Dec(18)),
                ("SIGSTOP", V::Dec(19)),
                ("SIGTSTP", V::Dec(20)),
                ("SIGTTIN", V::Dec(21)),
                ("SIGTTOU", V::Dec(22)),
                ("SIGURG", V::Dec(23)),
                ("SIGXCPU", V::Dec(24)),
                ("SIGXFSZ", V::Dec(25)),
                ("SIGVTALRM", V::Dec(26)),
                ("SIGPROF", V::Dec(27)),
                ("SIGWINCH", V::Dec(28)),
                ("SIGPOLL", V::Dec(29)),
                ("SIGIO", V::Txt("SIGPOLL")),
                ("SIGPWR", V::Dec(30)),
                ("SIGSYS", V::Dec(31)),
                ("__SIGRTMIN", V::Dec(32)),
                ("__SIGRTMAX", V::Dec(64)),
                ("_NSIG", V::Txt("(__SIGRTMAX + 1)")),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_SIG_MISC", items: &[
                    Item::Consts(&[
                        ("NSIG", V::Txt("_NSIG")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_SIG_POSIX", items: &[
                    Item::Include("<bits/types/sigset_t.h>"),
                    Item::Gate(&[
                        Branch { head: "ifndef _SIGSET_NWORDS", items: &[
                            Item::Consts(&[
                                ("_SIGSET_NWORDS", V::Txt("(1024 / (8 * sizeof (unsigned long int)))")),
                            ]),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifndef __pid_t_defined", items: &[
                            Item::Consts(&[
                                ("__pid_t_defined", V::Dec(1)),
                            ]),
                            Item::Typedef("int", "pid_t"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifndef __uid_t_defined", items: &[
                            Item::Consts(&[
                                ("__uid_t_defined", V::Dec(1)),
                            ]),
                            Item::Typedef("unsigned int", "uid_t"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifndef __clock_t_defined", items: &[
                            Item::Consts(&[
                                ("__clock_t_defined", V::Dec(1)),
                            ]),
                            Item::Typedef("long", "clock_t"),
                        ] },
                    ], ""),
                    Item::Include("<bits/types/struct_timespec.h>"),
                    Item::Include("<bits/types/siginfo_t.h>"),
                    Item::Include("<bits/types/struct_sigevent.h>"),
                    Item::Blank,
                    Item::Block { head: "enum ", body: &["", "  SI_ASYNCNL = -60,", "  SI_DETHREAD = -7,", "  SI_TKILL,", "  SI_SIGIO,", "  SI_ASYNCIO,", "  SI_MESGQ,", "  SI_TIMER,", "  SI_QUEUE,", "  SI_USER,", "  SI_KERNEL = 0x80", "# define SI_ASYNCNL SI_ASYNCNL", "# define SI_DETHREAD SI_DETHREAD", "# define SI_TKILL SI_TKILL", "# define SI_SIGIO SI_SIGIO", "# define SI_ASYNCIO SI_ASYNCIO", "# define SI_MESGQ SI_MESGQ", "# define SI_TIMER SI_TIMER", "# define SI_QUEUE SI_QUEUE", "# define SI_USER SI_USER", "# define SI_KERNEL SI_KERNEL", ""], tail: "" },
                    Item::Blank,
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_2K8", items: &[
                            Item::Block { head: "enum ", body: &["", "  ILL_ILLOPC = 1,", "#  define ILL_ILLOPC ILL_ILLOPC", "  ILL_ILLOPN,", "#  define ILL_ILLOPN ILL_ILLOPN", "  ILL_ILLADR,", "#  define ILL_ILLADR ILL_ILLADR", "  ILL_ILLTRP,", "#  define ILL_ILLTRP ILL_ILLTRP", "  ILL_PRVOPC,", "#  define ILL_PRVOPC ILL_PRVOPC", "  ILL_PRVREG,", "#  define ILL_PRVREG ILL_PRVREG", "  ILL_COPROC,", "#  define ILL_COPROC ILL_COPROC", "  ILL_BADSTK,", "#  define ILL_BADSTK ILL_BADSTK", "  ILL_BADIADDR", "#  define ILL_BADIADDR ILL_BADIADDR", ""], tail: "" },
                            Item::Block { head: "enum ", body: &["", "  FPE_INTDIV = 1,", "#  define FPE_INTDIV FPE_INTDIV", "  FPE_INTOVF,", "#  define FPE_INTOVF FPE_INTOVF", "  FPE_FLTDIV,", "#  define FPE_FLTDIV FPE_FLTDIV", "  FPE_FLTOVF,", "#  define FPE_FLTOVF FPE_FLTOVF", "  FPE_FLTUND,", "#  define FPE_FLTUND FPE_FLTUND", "  FPE_FLTRES,", "#  define FPE_FLTRES FPE_FLTRES", "  FPE_FLTINV,", "#  define FPE_FLTINV FPE_FLTINV", "  FPE_FLTSUB,", "#  define FPE_FLTSUB FPE_FLTSUB", "  FPE_FLTUNK = 14,", "#  define FPE_FLTUNK FPE_FLTUNK", "  FPE_CONDTRAP", "#  define FPE_CONDTRAP FPE_CONDTRAP", ""], tail: "" },
                            Item::Block { head: "enum ", body: &["", "  SEGV_MAPERR = 1,", "#  define SEGV_MAPERR SEGV_MAPERR", "  SEGV_ACCERR,", "#  define SEGV_ACCERR SEGV_ACCERR", "  SEGV_BNDERR,", "#  define SEGV_BNDERR SEGV_BNDERR", "  SEGV_PKUERR,", "#  define SEGV_PKUERR SEGV_PKUERR", "  SEGV_ACCADI,", "#  define SEGV_ACCADI SEGV_ACCADI", "  SEGV_ADIDERR,", "#  define SEGV_ADIDERR SEGV_ADIDERR", "  SEGV_ADIPERR,", "#  define SEGV_ADIPERR SEGV_ADIPERR", "  SEGV_MTEAERR,", "#  define SEGV_MTEAERR SEGV_MTEAERR", "  SEGV_MTESERR,", "#  define SEGV_MTESERR SEGV_MTESERR", "  SEGV_CPERR", "#  define SEGV_CPERR SEGV_CPERR", ""], tail: "" },
                            Item::Block { head: "enum ", body: &["", "  BUS_ADRALN = 1,", "#  define BUS_ADRALN BUS_ADRALN", "  BUS_ADRERR,", "#  define BUS_ADRERR BUS_ADRERR", "  BUS_OBJERR,", "#  define BUS_OBJERR BUS_OBJERR", "  BUS_MCEERR_AR,", "#  define BUS_MCEERR_AR BUS_MCEERR_AR", "  BUS_MCEERR_AO", "#  define BUS_MCEERR_AO BUS_MCEERR_AO", ""], tail: "" },
                            Item::Block { head: "enum ", body: &["", "  CLD_EXITED = 1,", "#  define CLD_EXITED CLD_EXITED", "  CLD_KILLED,", "#  define CLD_KILLED CLD_KILLED", "  CLD_DUMPED,", "#  define CLD_DUMPED CLD_DUMPED", "  CLD_TRAPPED,", "#  define CLD_TRAPPED CLD_TRAPPED", "  CLD_STOPPED,", "#  define CLD_STOPPED CLD_STOPPED", "  CLD_CONTINUED", "#  define CLD_CONTINUED CLD_CONTINUED", ""], tail: "" },
                            Item::Block { head: "enum ", body: &["", "  POLL_IN = 1,", "#  define POLL_IN POLL_IN", "  POLL_OUT,", "#  define POLL_OUT POLL_OUT", "  POLL_MSG,", "#  define POLL_MSG POLL_MSG", "  POLL_ERR,", "#  define POLL_ERR POLL_ERR", "  POLL_PRI,", "#  define POLL_PRI POLL_PRI", "  POLL_HUP", "#  define POLL_HUP POLL_HUP", ""], tail: "" },
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_XOPEN_EXT", items: &[
                            Item::Block { head: "enum ", body: &["", "  TRAP_BRKPT = 1,", "#  define TRAP_BRKPT TRAP_BRKPT", "  TRAP_TRACE,", "#  define TRAP_TRACE TRAP_TRACE", "  TRAP_BRANCH,", "#  define TRAP_BRANCH TRAP_BRANCH", "  TRAP_HWBKPT,", "#  define TRAP_HWBKPT TRAP_HWBKPT", "  TRAP_UNK,", "#  define TRAP_UNK TRAP_UNK", "  TRAP_PERF", "#  define TRAP_PERF TRAP_PERF", ""], tail: "" },
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_GNU", items: &[
                            Item::Block { head: "enum ", body: &["", "  SYS_SECCOMP = 1,", "#  define SYS_SECCOMP SYS_SECCOMP", "  SYS_USER_DISPATCH", "#  define SYS_USER_DISPATCH SYS_USER_DISPATCH", ""], tail: "" },
                        ] },
                    ], ""),
                    Item::Blank,
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_MISC", items: &[
                            Item::Include("<bits/types/__sigval_t.h>"),
                            Item::Typedef("__sigval_t", "sigval_t"),
                        ] },
                    ], ""),
                    Item::Blank,
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_GNU", items: &[
                            Item::Typedef("__sighandler_t", "sighandler_t"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_MISC", items: &[
                            Item::Typedef("__sighandler_t", "sig_t"),
                            Item::Raw(Reason::GlibcMacro, "#  define sigmask(sig) ((int)(1u << ((sig) - 1)))"),
                        ] },
                    ], ""),
                    Item::Blank,
                    Item::Block { head: "struct sigaction ", body: &["", "  union {", "    __sighandler_t sa_handler;", "    void (*sa_sigaction) (int, siginfo_t *, void *);", "  } __sigaction_handler;", "# define sa_handler __sigaction_handler.sa_handler", "# define sa_sigaction __sigaction_handler.sa_sigaction", "  __sigset_t sa_mask;", "  int sa_flags;", "  void (*sa_restorer) (void);", ""], tail: "" },
                    Item::Consts(&[
                        ("SA_NOCLDSTOP", V::Dec(1)),
                        ("SA_NOCLDWAIT", V::Dec(2)),
                        ("SA_SIGINFO", V::Dec(4)),
                    ]),
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_MISC", items: &[
                            Item::Consts(&[
                                ("SA_ONSTACK", V::Txt("0x08000000")),
                            ]),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_2K8", items: &[
                            Item::Consts(&[
                                ("SA_RESTART", V::Hex(0x10000000)),
                                ("SA_NODEFER", V::Hex(0x40000000)),
                                ("SA_RESETHAND", V::Hex(0x80000000)),
                            ]),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_MISC", items: &[
                            Item::Consts(&[
                                ("SA_INTERRUPT", V::Hex(0x20000000)),
                                ("SA_NOMASK", V::Txt("SA_NODEFER")),
                                ("SA_ONESHOT", V::Txt("SA_RESETHAND")),
                                ("SA_STACK", V::Txt("SA_ONSTACK")),
                            ]),
                        ] },
                    ], ""),
                    Item::Consts(&[
                        ("SIG_BLOCK", V::Dec(0)),
                        ("SIG_UNBLOCK", V::Dec(1)),
                        ("SIG_SETMASK", V::Dec(2)),
                    ]),
                    Item::Blank,
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_2K8", items: &[
                            Item::Include("<sys/ucontext.h>"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_SIG_XOPEN_EXT || defined __RLIBC_SIG_MISC", items: &[
                            Item::Include("<bits/types/stack_t.h>"),
                            Item::Consts(&[
                                ("MINSIGSTKSZ", V::Dec(2048)),
                                ("SIGSTKSZ", V::Dec(8192)),
                            ]),
                            Item::Gate(&[
                                Branch { head: "if defined _GNU_SOURCE || defined _DYNAMIC_STACK_SIZE_SOURCE", items: &[
                                    Item::Include("<unistd.h>"),
                                    Item::Undef("SIGSTKSZ"),
                                    Item::Consts(&[
                                        ("SIGSTKSZ", V::Txt("sysconf (_SC_SIGSTKSZ)")),
                                    ]),
                                    Item::Undef("MINSIGSTKSZ"),
                                    Item::Consts(&[
                                        ("MINSIGSTKSZ", V::Txt("SIGSTKSZ")),
                                    ]),
                                ] },
                            ], ""),
                            Item::Block { head: "enum ", body: &["", "  SS_ONSTACK = 1,", "#  define SS_ONSTACK SS_ONSTACK", "  SS_DISABLE", "#  define SS_DISABLE SS_DISABLE", ""], tail: "" },
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_SIG_MISC || (defined __RLIBC_SIG_XOPEN_EXT && !defined __RLIBC_SIG_2K8)", items: &[
                            Item::Include("<bits/types/struct_sigstack.h>"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_MISC", items: &[
                            Item::Include("<bits/sigcontext.h>"),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::Decl("extern int raise (int __sig);"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_SIG_MISC", items: &[
                    Item::Decl("extern __sighandler_t signal (int __sig, __sighandler_t __handler);"),
                ] },
                Branch { head: "else", items: &[
                    Item::Decl(r#"extern __sighandler_t signal (int __sig, __sighandler_t __handler) __asm__ ("__sysv_signal");"#),
                ] },
            ], ""),
            Item::Decl("extern __sighandler_t __sysv_signal (int __sig, __sighandler_t __handler);"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_SIG_POSIX", items: &[
                    Item::Include("<bits/rlibc-sigcalls-posix.h>"),
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_SIG_MISC || defined __RLIBC_SIG_XOPEN_EXT", items: &[
                            Item::Include("<bits/rlibc-sigcalls-misc.h>"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_MISC", items: &[
                            Item::Include("<bits/rlibc-sigcalls-miscx.h>"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_2K8", items: &[
                            Item::Include("<bits/rlibc-sigcalls-k8.h>"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_XOPEN_EXT", items: &[
                            Item::Include("<bits/rlibc-sigcalls-xopen.h>"),
                            Item::Decl(r#"extern int sigpause (int __sig) __asm__ ("__xpg_sigpause");"#),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_SIG_XOPEN_EXT && !defined __RLIBC_SIG_2K8", items: &[
                            Item::Include("<bits/rlibc-sigcalls-bsdsig.h>"),
                        ] },
                    ], ""),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_GNU", items: &[
                            Item::Include("<bits/rlibc-sigcalls-gnu.h>"),
                        ] },
                    ], ""),
                    Item::Decl("extern int pthread_sigmask (int __how, const sigset_t *__restrict __newmask, sigset_t *__restrict __oldmask);"),
                    Item::Decl("extern int pthread_kill (unsigned long int __threadid, int __signo);"),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_SIG_GNU", items: &[
                            Item::Decl("extern int pthread_sigqueue (unsigned long int __threadid, int __signo, const union sigval __value);"),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::Decl("extern int __libc_current_sigrtmin (void);"),
            Item::Decl("extern int __libc_current_sigrtmax (void);"),
            Item::Consts(&[
                ("SIGRTMIN", V::Txt("(__libc_current_sigrtmin ())")),
                ("SIGRTMAX", V::Txt("(__libc_current_sigrtmax ())")),
            ]),
            Item::Blank,
        ]},
    ],
};
