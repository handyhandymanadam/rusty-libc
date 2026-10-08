use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<bits/types/time_t.h>"),
    Item::Blank,
    Item::Block { head: "struct utimbuf ", body: &["", "  time_t actime;", "  time_t modtime;", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

