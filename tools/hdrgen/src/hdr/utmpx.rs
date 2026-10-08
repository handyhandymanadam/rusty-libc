use crate::model::*;

pub static HDR: Header = Header {
    path: "utmpx.h",
    items: &[
        Item::Guard { name: "_RLIBC_UTMPX_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<sys/types.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_GNU", items: &[
                    Item::Include("<paths.h>"),
                    Item::Consts(&[
                        ("_PATH_UTMPX", V::Txt("_PATH_UTMP")),
                        ("_PATH_WTMPX", V::Txt("_PATH_WTMP")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Consts(&[
                ("__UT_LINESIZE", V::Dec(32)),
                ("__UT_NAMESIZE", V::Dec(32)),
                ("__UT_HOSTSIZE", V::Dec(256)),
            ]),
            Item::Blank,
            Item::Block { head: "struct __exit_status ", body: &["", "#ifdef __RLIBC_USE_GNU", "  short int e_termination;", "  short int e_exit;", "#else", "  short int __e_termination;", "  short int __e_exit;", "#endif", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct utmpx ", body: &["", "  short int ut_type;", "  pid_t ut_pid;", "  char ut_line[__UT_LINESIZE];", "  char ut_id[4];", "  char ut_user[__UT_NAMESIZE];", "  char ut_host[__UT_HOSTSIZE];", "  struct __exit_status ut_exit;", "  int ut_session;", "  struct {", "    unsigned int tv_sec;", "    int tv_usec;", "  } ut_tv;", "  int ut_addr_v6[4];", "  char __glibc_reserved[20];", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("EMPTY", V::Dec(0)),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_GNU", items: &[
                    Item::Consts(&[
                        ("RUN_LVL", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Consts(&[
                ("BOOT_TIME", V::Dec(2)),
                ("NEW_TIME", V::Dec(3)),
                ("OLD_TIME", V::Dec(4)),
                ("INIT_PROCESS", V::Dec(5)),
                ("LOGIN_PROCESS", V::Dec(6)),
                ("USER_PROCESS", V::Dec(7)),
                ("DEAD_PROCESS", V::Dec(8)),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_GNU", items: &[
                    Item::Consts(&[
                        ("ACCOUNTING", V::Dec(9)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_GNU", items: &[
                    Item::Consts(&[
                        ("UTMPX_FILE", V::Txt("_PATH_UTMPX")),
                        ("UTMPX_FILENAME", V::Txt("_PATH_UTMPX")),
                        ("WTMPX_FILE", V::Txt("_PATH_WTMPX")),
                        ("WTMPX_FILENAME", V::Txt("_PATH_WTMPX")),
                    ]),
                    Item::Decl("struct utmp;"),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-utmpxcalls.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_GNU", items: &[
                    Item::Include("<bits/rlibc-utmpxcalls-misc.h>"),
                ] },
            ], ""),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
