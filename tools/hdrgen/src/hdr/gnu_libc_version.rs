use crate::model::*;

pub static HDR: Header = Header {
    path: "gnu/libc-version.h",
    items: &[
        Item::Guard { name: "_RLIBC_GNU_LIBC_VERSION_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::ExternBegin,
            Item::Decl("extern const char *gnu_get_libc_release (void) __attribute__ ((__nothrow__));"),
            Item::Decl("extern const char *gnu_get_libc_version (void) __attribute__ ((__nothrow__));"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
