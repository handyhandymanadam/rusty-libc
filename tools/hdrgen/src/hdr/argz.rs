use crate::model::*;

pub static HDR: Header = Header {
    path: "argz.h",
    items: &[
        Item::Comment(r#"/* argz.h for the Rust libc (crates/rusty-libc-extra/src/argz.rs): vectors of NUL separated strings; the
   prototypes are generated (bits/rlibc-argzcalls.h). */"#),
        Item::Guard { name: "_RLIBC_ARGZ_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<string.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __error_t_defined", items: &[
                    Item::Consts(&[
                        ("__error_t_defined", V::Dec(1)),
                    ]),
                    Item::Typedef("int", "error_t"),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-argzcalls.h>"),
            Item::Blank,
            Item::Comment("/* the names glibc exports for use by the inline versions of its header */"),
            Item::Decl("extern size_t __argz_count (const char *__argz, size_t __len);"),
            Item::Decl("extern void __argz_stringify (char *__argz, size_t __len, int __sep);"),
            Item::Decl("extern char *__argz_next (const char *__argz, size_t __argz_len, const char *__entry);"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
