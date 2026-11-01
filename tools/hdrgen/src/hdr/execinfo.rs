use crate::model::*;

pub static HDR: Header = Header {
    path: "execinfo.h",
    items: &[
        Item::Comment(r#"/* execinfo.h for the Rust libc (crates/rusty-libc-extra/src/backtrace.rs): stack traces of the calling thread.
   Written by hand (three prototypes). */"#),
        Item::Guard { name: "_RLIBC_EXECINFO_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Comment("/* Store up to SIZE return addresses of the current stack, innermost first, in ARRAY; their number. */"),
            Item::Decl("extern int backtrace (void **__array, int __size) __attribute__ ((__nonnull__ (1)));"),
            Item::Blank,
            Item::Comment(r#"/* Describe the addresses as strings ("file(symbol+0xoffset) [0xaddress]") in one malloc'd block. */"#),
            Item::Decl("extern char **backtrace_symbols (void *const *__array, int __size) __attribute__ ((__nothrow__, __nonnull__ (1)));"),
            Item::Blank,
            Item::Comment("/* The same, one line per address, written to the file descriptor FD (nothing is allocated). */"),
            Item::Decl("extern void backtrace_symbols_fd (void *const *__array, int __size, int __fd) __attribute__ ((__nothrow__, __nonnull__ (1)));"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
