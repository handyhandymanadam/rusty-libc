use crate::model::*;

pub static HDR: Header = Header {
    path: "setjmp.h",
    items: &[
        Item::Guard { name: "_RLIBC_SETJMP_H", value: "1", end: "", items: &[
            Item::Include("<bits/types/__sigset_t.h>"),
            Item::Blank,
            Item::Decl("typedef long int __jmp_buf[8];"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __jmp_buf_tag_defined", items: &[
                    Item::Consts(&[
                        ("__jmp_buf_tag_defined", V::Dec(1)),
                    ]),
                    Item::Block { head: "struct __jmp_buf_tag ", body: &["", "  __jmp_buf __jmpbuf;", "  int __mask_was_saved;", "  __sigset_t __saved_mask;", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::Decl("typedef struct __jmp_buf_tag jmp_buf[1];"),
            Item::Blank,
            Item::Decl("extern int setjmp (jmp_buf __env);"),
            Item::Decl("extern int __sigsetjmp (struct __jmp_buf_tag __env[1], int __savemask);"),
            Item::Decl("extern int _setjmp (struct __jmp_buf_tag __env[1]);"),
            Item::Raw(Reason::GlibcMacro, "#define setjmp(env) _setjmp (env)"),
            Item::Blank,
            Item::Decl("extern void longjmp (struct __jmp_buf_tag __env[1], int __val) __attribute__ ((__noreturn__));"),
            Item::Decl("extern void __longjmp_chk (struct __jmp_buf_tag __env[1], int __val) __attribute__ ((__noreturn__));"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE || defined _XOPEN_SOURCE \
    || !defined __STRICT_ANSI__"#, items: &[
                    Item::Decl("extern void _longjmp (struct __jmp_buf_tag __env[1], int __val) __attribute__ ((__noreturn__));"),
                    Item::Decl("typedef struct __jmp_buf_tag sigjmp_buf[1];"),
                    Item::Raw(Reason::GlibcMacro, "# define sigsetjmp(env, savemask) __sigsetjmp (env, savemask)"),
                    Item::Decl("extern void siglongjmp (sigjmp_buf __env, int __val) __attribute__ ((__noreturn__));"),
                ] },
            ], ""),
        ]},
    ],
};
