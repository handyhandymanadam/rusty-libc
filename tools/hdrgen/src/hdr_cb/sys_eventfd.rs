use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* constants (values checked against glibc by tests/c/sys_consts.c) */"),
    Item::Consts(&[
        ("EFD_SEMAPHORE", V::Dec(1)),
        ("EFD_CLOEXEC", V::Hex(0x80000)),
        ("EFD_NONBLOCK", V::Dec(2048)),
    ]),
    Item::Blank,
    Item::Comment("/* written by hand: types, unions, macros with arguments */"),
    Item::Typedef("uint64_t", "eventfd_t"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

