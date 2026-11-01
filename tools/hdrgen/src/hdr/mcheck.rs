use crate::model::*;

pub static HDR: Header = Header {
    path: "mcheck.h",
    items: &[
        Item::Comment(r#"/* mcheck.h for the Rust libc (crates/rusty-libc-extra/src/misc.rs): heap consistency checking. As in glibc 2.43's
   libc, the functions only report that checking is not enabled (mcheck: -1, mprobe: MCHECK_DISABLED). */"#),
        Item::Guard { name: "_RLIBC_MCHECK_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Comment("/* Return values for `mprobe'. */"),
            Item::Block { head: "enum mcheck_status ", body: &["", "  MCHECK_DISABLED = -1,         /* Consistency checking is not turned on.  */", "  MCHECK_OK,                    /* Block is fine.  */", "  MCHECK_FREE,                  /* Block freed twice.  */", "  MCHECK_HEAD,                  /* Memory before the block was clobbered.  */", "  MCHECK_TAIL                   /* Memory after the block was clobbered.  */", ""], tail: "" },
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
