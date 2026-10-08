use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Decl("extern char *program_invocation_name;"),
    Item::Decl("extern char *program_invocation_short_name;"),
    Item::Decl("extern char *__progname;"),
    Item::Decl("extern char *__progname_full;"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

pub static TRAILER: &[Item] = &[
    Item::Consts(&[
        ("errno", V::Txt("(*__errno_location())")),
    ]),
];
pub const TRAILER_CHOMP: bool = true;

