use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("SWAP_FLAG_PREFER", V::Hex(0x8000)),
        ("SWAP_FLAG_PRIO_MASK", V::Hex(0x7fff)),
        ("SWAP_FLAG_PRIO_SHIFT", V::Dec(0)),
        ("SWAP_FLAG_DISCARD", V::Hex(0x10000)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

