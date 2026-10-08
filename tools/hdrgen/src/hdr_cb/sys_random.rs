use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("GRND_NONBLOCK", V::Txt("0x01")),
        ("GRND_RANDOM", V::Txt("0x02")),
        ("GRND_INSECURE", V::Txt("0x04")),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

