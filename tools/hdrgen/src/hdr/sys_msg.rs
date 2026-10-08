use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/msg.h",
    items: &[
        Item::Guard { name: "_SYS_MSG_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<sys/ipc.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE", items: &[
                    Item::Consts(&[
                        ("__RLIBC_MSG_GNU", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_MSG_MISC", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Typedef("unsigned long int", "msgqnum_t"),
            Item::Typedef("unsigned long int", "msglen_t"),
            Item::Blank,
            Item::Block { head: "struct msqid_ds ", body: &["", "  struct ipc_perm msg_perm;", "  time_t msg_stime;", "  time_t msg_rtime;", "  time_t msg_ctime;", "  unsigned long int __msg_cbytes;", "  msgqnum_t msg_qnum;", "  msglen_t msg_qbytes;", "  pid_t msg_lspid;", "  pid_t msg_lrpid;", "  unsigned long int __glibc_reserved4;", "  unsigned long int __glibc_reserved5;", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("MSG_NOERROR", V::Txt("010000")),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MSG_GNU", items: &[
                    Item::Consts(&[
                        ("MSG_EXCEPT", V::Txt("020000")),
                        ("MSG_COPY", V::Txt("040000")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MSG_MISC", items: &[
                    Item::Consts(&[
                        ("msg_cbytes", V::Txt("__msg_cbytes")),
                        ("MSG_STAT", V::Dec(11)),
                        ("MSG_INFO", V::Dec(12)),
                        ("MSG_STAT_ANY", V::Dec(13)),
                    ]),
                    Item::Block { head: "struct msginfo ", body: &["", "  int msgpool;", "  int msgmap;", "  int msgmax;", "  int msgmnb;", "  int msgmni;", "  int msgssz;", "  int msgtql;", "  unsigned short int msgseg;", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MSG_GNU", items: &[
                    Item::Block { head: "struct msgbuf ", body: &["", "  long int mtype;", "  char mtext[1];", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-ipc-msg.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
