use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* constants (values checked against glibc by tests/c/sys_consts.c) */"),
    Item::Consts(&[
        ("UL_GETFSIZE", V::Dec(1)),
        ("UL_SETFSIZE", V::Dec(2)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

