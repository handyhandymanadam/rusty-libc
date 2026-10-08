use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<bits/types/locale_t.h>"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

pub static TRAILER: &[Item] = &[
    Item::Gate(&[
        Branch { head: "if __GNUC_PREREQ (3,4) && __USE_FORTIFY_LEVEL > 0 && defined __fortify_function", items: &[
            Item::Gate(&[
                Branch { head: "if defined __USE_MISC || !defined __USE_XOPEN2K8", items: &[
                    Item::Include("<bits/strings_fortified.h>"),
                ] },
            ], ""),
        ] },
    ], ""),
];
pub const TRAILER_CHOMP: bool = false;
