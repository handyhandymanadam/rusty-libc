use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/__locale_t.h",
    items: &[
        Item::Guard { name: "_BITS_TYPES___LOCALE_T_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Decl("struct __locale_data;"),
            Item::Block { head: "struct __locale_struct\n", body: &["", "  struct __locale_data *__locales[13];", "  const unsigned short int *__ctype_b;", "  const int *__ctype_tolower;", "  const int *__ctype_toupper;", "  const char *__names[13];", ""], tail: "" },
            Item::Blank,
            Item::Typedef("struct __locale_struct *", "__locale_t"),
        ]},
    ],
};
