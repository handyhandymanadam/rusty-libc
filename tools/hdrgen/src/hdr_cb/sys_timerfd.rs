use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("TFD_CLOEXEC", V::Hex(0x80000)),
        ("TFD_NONBLOCK", V::Dec(2048)),
        ("TFD_TIMER_ABSTIME", V::Dec(1)),
        ("TFD_TIMER_CANCEL_ON_SET", V::Dec(2)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

