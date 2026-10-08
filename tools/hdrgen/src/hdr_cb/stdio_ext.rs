use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("FSETLOCKING_QUERY", V::Dec(0)),
        ("FSETLOCKING_INTERNAL", V::Dec(1)),
        ("FSETLOCKING_BYCALLER", V::Dec(2)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

