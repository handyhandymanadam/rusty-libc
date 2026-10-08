use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Decl("extern char *program_invocation_name;"),
    Item::Decl("extern char *program_invocation_short_name;"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

