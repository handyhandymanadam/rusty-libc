use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* constants (values checked against glibc by tests/c/sys_consts.c) */"),
    Item::Consts(&[
        ("ACCT_COMM", V::Dec(16)),
        ("ACCT_BYTEORDER", V::Txt("0x00")),
        ("AHZ", V::Dec(100)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

