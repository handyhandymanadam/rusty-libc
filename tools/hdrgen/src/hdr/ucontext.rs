use crate::model::*;

pub static HDR: Header = Header {
    path: "ucontext.h",
    items: &[
        Item::Guard { name: "_RLIBC_UCONTEXT_H", value: "1", end: "", items: &[
            Item::Include("<sys/ucontext.h>"),
            Item::Blank,
            Item::Decl("extern int getcontext (ucontext_t *__ucp);"),
            Item::Decl("extern int setcontext (const ucontext_t *__ucp);"),
            Item::Decl("extern int swapcontext (ucontext_t *__restrict __oucp, const ucontext_t *__restrict __ucp);"),
            Item::Decl("extern void makecontext (ucontext_t *__ucp, void (*__func) (void), int __argc, ...);"),
        ]},
    ],
};
