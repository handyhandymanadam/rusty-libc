use crate::model::*;

pub static HDR: Header = Header {
    path: "envz.h",
    items: &[
        Item::Comment(r#"/* envz.h for the Rust libc (crates/rusty-libc-extra/src/argz.rs): argz vectors of NAME=value entries; the
   prototypes are generated (bits/rlibc-envzcalls.h). */"#),
        Item::Guard { name: "_RLIBC_ENVZ_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<argz.h>"),
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-envzcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
