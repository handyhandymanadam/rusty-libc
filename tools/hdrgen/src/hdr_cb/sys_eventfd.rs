use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("EFD_SEMAPHORE", V::Dec(1)),
        ("EFD_CLOEXEC", V::Hex(0x80000)),
        ("EFD_NONBLOCK", V::Dec(2048)),
    ]),
    Item::Blank,
    Item::Typedef("uint64_t", "eventfd_t"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

