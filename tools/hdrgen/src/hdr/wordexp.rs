use crate::model::*;

pub static HDR: Header = Header {
    path: "wordexp.h",
    items: &[
        Item::Guard { name: "_RLIBC_WORDEXP_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Consts(&[
                ("__need_size_t", V::Txt("")),
            ]),
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  WRDE_DOOFFS = (1 << 0),", "  WRDE_APPEND = (1 << 1),", "  WRDE_NOCMD = (1 << 2),", "  WRDE_REUSE = (1 << 3),", "  WRDE_SHOWERR = (1 << 4),", "  WRDE_UNDEF = (1 << 5),", "  __WRDE_FLAGS = (WRDE_DOOFFS | WRDE_APPEND | WRDE_NOCMD | WRDE_REUSE | WRDE_SHOWERR | WRDE_UNDEF)", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "typedef struct ", body: &["", "  size_t we_wordc;", "  char **we_wordv;", "  size_t we_offs;", ""], tail: " wordexp_t" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "#ifdef __USE_XOPEN", "  WRDE_NOSYS = -1,", "#endif", "  WRDE_NOSPACE = 1,", "  WRDE_BADCHAR,", "  WRDE_BADVAL,", "  WRDE_CMDSUB,", "  WRDE_SYNTAX", ""], tail: "" },
            Item::Blank,
            Item::Include("<bits/rlibc-wordexpcalls.h>"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
