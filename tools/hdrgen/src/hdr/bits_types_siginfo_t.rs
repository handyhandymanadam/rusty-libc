use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/siginfo_t.h",
    items: &[
        Item::Guard { name: "_RLIBC_SIGINFO_T_H", value: "1", end: "", items: &[
            Item::Gate(&[
                Branch { head: "ifndef __siginfo_t_defined", items: &[
                    Item::Consts(&[
                        ("__siginfo_t_defined", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Include("<bits/types/__sigval_t.h>"),
            Item::Consts(&[
                ("__SI_MAX_SIZE", V::Dec(128)),
                ("__SI_PAD_SIZE", V::Txt("((__SI_MAX_SIZE / sizeof (int)) - 4)")),
            ]),
            Item::Block { head: "typedef struct ", body: &["", "  int si_signo;", "  int si_errno;", "  int si_code;", "  int __pad0;", "  union {", "    int _pad[__SI_PAD_SIZE];", "    struct {", "      int si_pid;", "      unsigned int si_uid;", "    } _kill;", "    struct {", "      int si_tid;", "      int si_overrun;", "      __sigval_t si_sigval;", "    } _timer;", "    struct {", "      int si_pid;", "      unsigned int si_uid;", "      __sigval_t si_sigval;", "    } _rt;", "    struct {", "      int si_pid;", "      unsigned int si_uid;", "      int si_status;", "      long si_utime;", "      long si_stime;", "    } _sigchld;", "    struct {", "      void *si_addr;", "      short int si_addr_lsb;", "      union {", "        struct {", "          void *_lower;", "          void *_upper;", "        } _addr_bnd;", "        unsigned int _pkey;", "      } _bounds;", "    } _sigfault;", "    struct {", "      long int si_band;", "      int si_fd;", "    } _sigpoll;", "    struct {", "      void *_call_addr;", "      int _syscall;", "      unsigned int _arch;", "    } _sigsys;", "  } _sifields;", ""], tail: " siginfo_t" },
            Item::Consts(&[
                ("si_pid", V::Txt("_sifields._kill.si_pid")),
                ("si_uid", V::Txt("_sifields._kill.si_uid")),
                ("si_timerid", V::Txt("_sifields._timer.si_tid")),
                ("si_overrun", V::Txt("_sifields._timer.si_overrun")),
                ("si_status", V::Txt("_sifields._sigchld.si_status")),
                ("si_utime", V::Txt("_sifields._sigchld.si_utime")),
                ("si_stime", V::Txt("_sifields._sigchld.si_stime")),
                ("si_value", V::Txt("_sifields._rt.si_sigval")),
                ("si_int", V::Txt("_sifields._rt.si_sigval.sival_int")),
                ("si_ptr", V::Txt("_sifields._rt.si_sigval.sival_ptr")),
                ("si_addr", V::Txt("_sifields._sigfault.si_addr")),
                ("si_addr_lsb", V::Txt("_sifields._sigfault.si_addr_lsb")),
                ("si_lower", V::Txt("_sifields._sigfault._bounds._addr_bnd._lower")),
                ("si_upper", V::Txt("_sifields._sigfault._bounds._addr_bnd._upper")),
                ("si_pkey", V::Txt("_sifields._sigfault._bounds._pkey")),
                ("si_band", V::Txt("_sifields._sigpoll.si_band")),
                ("si_fd", V::Txt("_sifields._sigpoll.si_fd")),
                ("si_call_addr", V::Txt("_sifields._sigsys._call_addr")),
                ("si_syscall", V::Txt("_sifields._sigsys._syscall")),
                ("si_arch", V::Txt("_sifields._sigsys._arch")),
            ]),
        ]},
    ],
};
