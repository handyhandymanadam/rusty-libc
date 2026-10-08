use crate::model::*;

pub static HDR: Header = Header {
    path: "monetary.h",
    items: &[
        Item::Guard { name: "_RLIBC_MONETARY_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<stddef.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<bits/types/locale_t.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Decl(r#"extern ssize_t strfmon (char *__restrict __s, size_t __maxsize, const char *__restrict __format, ...)
  __attribute__ ((__nothrow__, __format__ (__strfmon__, 3, 4)));"#),
            Item::Blank,
            Item::Decl(r#"extern ssize_t strfmon_l (char *__restrict __s, size_t __maxsize, locale_t __loc, const char *__restrict __format, ...)
  __attribute__ ((__nothrow__, __format__ (__strfmon__, 4, 5)));"#),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
