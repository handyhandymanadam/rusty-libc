use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<bits/types/time_t.h>"),
    Item::Blank,
    Item::Block { head: "struct timeb ", body: &["", "  time_t time;", "  unsigned short millitm;", "  short timezone;", "  short dstflag;", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

