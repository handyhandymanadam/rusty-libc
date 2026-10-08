use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<stdlib.h>"),
    Item::Include("<stdio.h>"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

