use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* constants (values checked against glibc by tests/c/sys_consts.c) */"),
    Item::Consts(&[
        ("UIO_MAXIOV", V::Dec(1024)),
        ("RWF_HIPRI", V::Txt("0x00000001")),
        ("RWF_DSYNC", V::Txt("0x00000002")),
        ("RWF_SYNC", V::Txt("0x00000004")),
        ("RWF_NOWAIT", V::Txt("0x00000008")),
        ("RWF_APPEND", V::Txt("0x00000010")),
        ("RWF_NOAPPEND", V::Txt("0x00000020")),
        ("RWF_ATOMIC", V::Txt("0x00000040")),
        ("RWF_DONTCACHE", V::Txt("0x00000080")),
    ]),
    Item::Blank,
    Item::Comment("/* written by hand: types, unions, macros with arguments */"),
    Item::Consts(&[
        ("UIO_MAXIOV", V::Dec(1024)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

