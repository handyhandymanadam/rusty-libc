use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Typedef("void *", "iconv_t"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

