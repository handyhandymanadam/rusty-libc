use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("XATTR_CREATE", V::Dec(1)),
        ("XATTR_REPLACE", V::Dec(2)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

