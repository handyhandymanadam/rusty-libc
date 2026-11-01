use crate::model::*;

pub static HDR: Header = Header {
    path: "gnu/libc-version.h",
    items: &[
        Item::Comment("/* gnu/libc-version.h for the Rust libc (crates/rusty-libc-extra/src/misc.rs): the version this library follows. */"),
        Item::Guard { name: "_RLIBC_GNU_LIBC_VERSION_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::ExternBegin,
            Item::Comment(r#"/* "stable" */"#),
            Item::Decl("extern const char *gnu_get_libc_release (void) __attribute__ ((__nothrow__));"),
            Item::Comment(r#"/* "2.43": the glibc version whose behaviour this library follows */"#),
            Item::Decl("extern const char *gnu_get_libc_version (void) __attribute__ ((__nothrow__));"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
