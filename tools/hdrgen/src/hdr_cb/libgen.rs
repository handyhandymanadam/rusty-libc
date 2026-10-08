use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<string.h>"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

pub static TRAILER: &[Item] = &[
    Item::Consts(&[
        ("basename", V::Txt("__xpg_basename")),
    ]),
];
pub const TRAILER_CHOMP: bool = true;

