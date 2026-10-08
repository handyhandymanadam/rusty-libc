use crate::model::*;

pub static HDR: Header = Header {
    path: "mcheck.h",
    items: &[
        Item::Guard { name: "_RLIBC_MCHECK_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: "enum mcheck_status ", body: &["", "  MCHECK_DISABLED = -1,", "  MCHECK_OK,", "  MCHECK_FREE,", "  MCHECK_HEAD,", "  MCHECK_TAIL", ""], tail: "" },
            Item::Blank,
            Item::Decl("extern int mcheck (void (*__abortfunc)(enum mcheck_status)) __attribute__ ((__nothrow__));"),
            Item::Decl("extern int mcheck_pedantic (void (*__abortfunc)(enum mcheck_status)) __attribute__ ((__nothrow__));"),
            Item::Decl("extern void mcheck_check_all (void);"),
            Item::Decl("extern enum mcheck_status mprobe (void *__ptr) __attribute__ ((__nothrow__));"),
            Item::Decl("extern void mtrace (void) __attribute__ ((__nothrow__));"),
            Item::Decl("extern void muntrace (void) __attribute__ ((__nothrow__));"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
