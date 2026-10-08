use crate::model::*;

pub static HDR: Header = Header {
    path: "execinfo.h",
    items: &[
        Item::Guard { name: "_RLIBC_EXECINFO_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Decl("extern int backtrace (void **__array, int __size) __attribute__ ((__nonnull__ (1)));"),
            Item::Blank,
            Item::Decl("extern char **backtrace_symbols (void *const *__array, int __size) __attribute__ ((__nothrow__, __nonnull__ (1)));"),
            Item::Blank,
            Item::Decl("extern void backtrace_symbols_fd (void *const *__array, int __size, int __fd) __attribute__ ((__nothrow__, __nonnull__ (1)));"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
