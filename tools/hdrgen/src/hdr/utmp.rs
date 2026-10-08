use crate::model::*;

pub static HDR: Header = Header {
    path: "utmp.h",
    items: &[
        Item::Guard { name: "_RLIBC_UTMP_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<paths.h>"),
            Item::Blank,
            Item::Consts(&[
                ("UT_LINESIZE", V::Dec(32)),
                ("UT_NAMESIZE", V::Dec(32)),
                ("UT_HOSTSIZE", V::Dec(256)),
            ]),
            Item::Blank,
            Item::Block { head: "struct lastlog ", body: &["", "  unsigned int ll_time;", "  char ll_line[UT_LINESIZE];", "  char ll_host[UT_HOSTSIZE];", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct exit_status ", body: &["", "  short int e_termination;", "  short int e_exit;", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct utmp ", body: &["", "  short int ut_type;", "  pid_t ut_pid;", "  char ut_line[UT_LINESIZE];", "  char ut_id[4];", "  char ut_user[UT_NAMESIZE];", "  char ut_host[UT_HOSTSIZE];", "  struct exit_status ut_exit;", "  int ut_session;", "  struct {", "    unsigned int tv_sec;", "    int tv_usec;", "  } ut_tv;", "  int ut_addr_v6[4];", "  char __glibc_reserved[20];", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("ut_name", V::Txt("ut_user")),
            ]),
            Item::Gate(&[
                Branch { head: "ifndef _NO_UT_TIME", items: &[
                    Item::Consts(&[
                        ("ut_time", V::Txt("ut_tv.tv_sec")),
                    ]),
                ] },
            ], ""),
            Item::Consts(&[
                ("ut_xtime", V::Txt("ut_tv.tv_sec")),
                ("ut_addr", V::Txt("ut_addr_v6[0]")),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("EMPTY", V::Dec(0)),
                ("RUN_LVL", V::Dec(1)),
                ("BOOT_TIME", V::Dec(2)),
                ("NEW_TIME", V::Dec(3)),
                ("OLD_TIME", V::Dec(4)),
                ("INIT_PROCESS", V::Dec(5)),
                ("LOGIN_PROCESS", V::Dec(6)),
                ("USER_PROCESS", V::Dec(7)),
                ("DEAD_PROCESS", V::Dec(8)),
                ("ACCOUNTING", V::Dec(9)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("UT_UNKNOWN", V::Txt("EMPTY")),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("_HAVE_UT_TYPE", V::Dec(1)),
                ("_HAVE_UT_PID", V::Dec(1)),
                ("_HAVE_UT_ID", V::Dec(1)),
                ("_HAVE_UT_TV", V::Dec(1)),
                ("_HAVE_UT_HOST", V::Dec(1)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("UTMP_FILE", V::Txt("_PATH_UTMP")),
                ("UTMP_FILENAME", V::Txt("_PATH_UTMP")),
                ("WTMP_FILE", V::Txt("_PATH_WTMP")),
                ("WTMP_FILENAME", V::Txt("_PATH_WTMP")),
            ]),
            Item::Blank,
            Item::ExternBegin,
            Item::Decl("extern int login_tty (int __fd);"),
            Item::Include("<bits/rlibc-utmpcalls.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_MISC", items: &[
                    Item::Include("<bits/rlibc-utmpcalls-misc.h>"),
                ] },
            ], ""),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
