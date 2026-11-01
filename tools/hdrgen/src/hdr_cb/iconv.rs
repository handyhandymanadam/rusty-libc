use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* Identifier for conversion method from one codeset to another. */"),
    Item::Typedef("void *", "iconv_t"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

