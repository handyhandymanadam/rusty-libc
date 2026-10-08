use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("FNM_PATHNAME", V::Txt("(1 << 0)")),
        ("FNM_NOESCAPE", V::Txt("(1 << 1)")),
        ("FNM_PERIOD", V::Txt("(1 << 2)")),
        ("FNM_FILE_NAME", V::Txt("FNM_PATHNAME")),
        ("FNM_LEADING_DIR", V::Txt("(1 << 3)")),
        ("FNM_CASEFOLD", V::Txt("(1 << 4)")),
        ("FNM_EXTMATCH", V::Txt("(1 << 5)")),
        ("FNM_NOMATCH", V::Dec(1)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

