use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* The program name that err/warn/error print (set by the startup code from argv[0]). */"),
    Item::Decl("extern char *program_invocation_name;"),
    Item::Decl("extern char *program_invocation_short_name;"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

