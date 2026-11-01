use crate::model::*;

pub static HDR: Header = Header {
    path: "monetary.h",
    items: &[
        Item::Comment(r#"/* monetary.h for the Rust libc (crates/rusty-libc-extra/src/strfmon.rs): formatting of monetary values.
   Written by hand (two prototypes with ssize_t and a locale_t). */"#),
        Item::Guard { name: "_RLIBC_MONETARY_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<stddef.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<bits/types/locale_t.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Comment(r#"/* Format the values of the arguments into S (at most MAXSIZE bytes, the NUL included) following FORMAT:
   %n national and %i international format, with flags, width, #left precision and .right precision.
   Returns the length without the NUL, or -1 with errno EINVAL (bad format) or E2BIG (does not fit). */"#),
            Item::Decl(r#"extern ssize_t strfmon (char *__restrict __s, size_t __maxsize, const char *__restrict __format, ...)
  __attribute__ ((__nothrow__, __format__ (__strfmon__, 3, 4)));"#),
            Item::Blank,
            Item::Comment("/* The same with the conventions of the locale LOC. */"),
            Item::Decl(r#"extern ssize_t strfmon_l (char *__restrict __s, size_t __maxsize, locale_t __loc, const char *__restrict __format, ...)
  __attribute__ ((__nothrow__, __format__ (__strfmon__, 4, 5)));"#),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
