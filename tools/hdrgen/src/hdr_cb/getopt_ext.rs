use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Block { head: "struct option ", body: &["", "  const char *name;", "", "  int has_arg;", "  int *flag;", "  int val;", ""], tail: "" },
    Item::Blank,
    Item::Consts(&[
        ("no_argument", V::Dec(0)),
        ("required_argument", V::Dec(1)),
        ("optional_argument", V::Dec(2)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

