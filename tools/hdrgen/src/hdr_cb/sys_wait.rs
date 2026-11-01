use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* constants (values checked against glibc by tests/c/sys_consts.c) */"),
    Item::Include("<bits/waitflags.h>"),
    Item::Gate(&[
        Branch { head: "ifdef __USE_XOPEN2K8", items: &[
            Item::Include("<signal.h>   /* glibc: siginfo_t and the signal numbers come with <sys/wait.h> */"),
        ] },
    ], ""),
    Item::Include("<bits/waitstatus.h>"),
    Item::Consts(&[
        ("WAIT_ANY", V::Dec(-1)),
        ("WAIT_MYPGRP", V::Dec(0)),
    ]),
    Item::Blank,
    Item::Comment("/* written by hand: types, unions, macros with arguments */"),
    Item::Block { head: "typedef enum ", body: &["", "  P_ALL,", "  P_PID,", "  P_PGID,", "  P_PIDFD", ""], tail: " idtype_t" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

