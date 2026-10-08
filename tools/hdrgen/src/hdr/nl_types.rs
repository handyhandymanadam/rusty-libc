use crate::model::*;

pub static HDR: Header = Header {
    path: "nl_types.h",
    items: &[
        Item::Guard { name: "_RLIBC_NL_TYPES_H", value: "1", end: "", items: &[
            Item::ExternBegin,
            Item::Consts(&[
                ("NL_SETD", V::Dec(1)),
                ("NL_CAT_LOCALE", V::Dec(1)),
            ]),
            Item::Typedef("void *", "nl_catd"),
            Item::Typedef("int", "nl_item"),
            Item::Decl("extern nl_catd catopen (const char *__cat_name, int __flag);"),
            Item::Decl("extern char *catgets (nl_catd __catalog, int __set, int __number, const char *__string);"),
            Item::Decl("extern int catclose (nl_catd __catalog);"),
            Item::ExternEnd,
        ]},
    ],
};
