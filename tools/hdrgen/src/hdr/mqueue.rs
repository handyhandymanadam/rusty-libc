use crate::model::*;

pub static HDR: Header = Header {
    path: "mqueue.h",
    items: &[
        Item::Guard { name: "_MQUEUE_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<fcntl.h>"),
            Item::Include("<bits/types/struct_sigevent.h>"),
            Item::Include("<bits/types/struct_timespec.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || (!defined __STRICT_ANSI__ && !defined _POSIX_SOURCE && !defined _POSIX_C_SOURCE && !defined _XOPEN_SOURCE) \
    || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200112L) || (defined _XOPEN_SOURCE && _XOPEN_SOURCE >= 600)"#, items: &[
                    Item::Consts(&[
                        ("__RLIBC_MQ_XOPEN2K", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Typedef("int", "mqd_t"),
            Item::Blank,
            Item::Block { head: "struct mq_attr ", body: &["", "  long int mq_flags;", "  long int mq_maxmsg;", "  long int mq_msgsize;", "  long int mq_curmsgs;", "  long int __pad[4];", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-mq-calls.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MQ_XOPEN2K", items: &[
                    Item::Include("<bits/rlibc-mq-timed.h>"),
                ] },
            ], ""),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
