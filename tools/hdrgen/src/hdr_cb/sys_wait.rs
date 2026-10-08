use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<bits/waitflags.h>"),
    Item::Gate(&[
        Branch { head: "ifdef __USE_XOPEN2K8", items: &[
            Item::Include("<signal.h>"),
        ] },
    ], ""),
    Item::Include("<bits/waitstatus.h>"),
    Item::Consts(&[
        ("WAIT_ANY", V::Dec(-1)),
        ("WAIT_MYPGRP", V::Dec(0)),
    ]),
    Item::Blank,
    Item::Block { head: "typedef enum ", body: &["", "  P_ALL,", "  P_PID,", "  P_PGID,", "  P_PIDFD", ""], tail: " idtype_t" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

