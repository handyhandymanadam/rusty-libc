use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* <string.h> declares the GNU basename; it must come before the macro below renames the POSIX one. */"),
    Item::Include("<string.h>"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

pub static TRAILER: &[Item] = &[
    Item::Comment(r#"/* POSIX basename (this header) and GNU basename (<string.h>) share a name: like glibc, including
   <libgen.h> selects the POSIX one. */"#),
    Item::Consts(&[
        ("basename", V::Txt("__xpg_basename")),
    ]),
];
pub const TRAILER_CHOMP: bool = true;

