use crate::model::*;

pub static HDR: Header = Header {
    path: "alloca.h",
    items: &[
        Item::Guard { name: "_ALLOCA_H", value: "1", end: "", items: &[
            Item::Include("<stddef.h>"),
            Item::ExternBegin,
            Item::Decl("extern void *alloca (size_t __size) __attribute__ ((__nothrow__));"),
            Item::ExternEnd,
            Item::Gate(&[
                Branch { head: "ifdef __GNUC__", items: &[
                    Item::Undef("alloca"),
                    Item::Raw(Reason::GlibcMacro, "# define alloca(size) __builtin_alloca (size)"),
                ] },
            ], ""),
        ]},
    ],
};
