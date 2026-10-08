use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Gate(&[
        Branch { head: "ifdef __USE_MISC", items: &[
            Item::Include("<fcntl.h>"),
        ] },
    ], ""),
    Item::Consts(&[
        ("L_SET", V::Dec(0)),
        ("L_INCR", V::Dec(1)),
        ("L_XTND", V::Dec(2)),
        ("LOCK_SH", V::Dec(1)),
        ("LOCK_EX", V::Dec(2)),
        ("LOCK_UN", V::Dec(8)),
        ("LOCK_NB", V::Dec(4)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

