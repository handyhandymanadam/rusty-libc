use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Gate(&[
        Branch { head: "ifdef __USE_MISC", items: &[
            Item::Include("<strings.h>"),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "ifdef _GNU_SOURCE", items: &[
            Item::Decl("char *strerror_r(int, char *, size_t);"),
        ] },
        Branch { head: "else", items: &[
            Item::Decl(r#"int strerror_r(int, char *, size_t) __asm__("__xpg_strerror_r");"#),
        ] },
    ], ""),
    Item::Decl("extern int __memcmpeq(const void *, const void *, size_t);"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

pub static TRAILER: &[Item] = &[
    Item::Gate(&[
        Branch { head: "if __GLIBC_USE (ISOC23) && defined __glibc_const_generic && !defined _LIBC", items: &[
            Item::Raw(Reason::GlibcMacro, "# define memchr(S, C, N) __glibc_const_generic (S, const void *, memchr (S, C, N))"),
            Item::Raw(Reason::GlibcMacro, "# define strchr(S, C) __glibc_const_generic (S, const char *, strchr (S, C))"),
            Item::Raw(Reason::GlibcMacro, "# define strrchr(S, C) __glibc_const_generic (S, const char *, strrchr (S, C))"),
            Item::Raw(Reason::GlibcMacro, "# define strpbrk(S, ACCEPT) __glibc_const_generic (S, const char *, strpbrk (S, ACCEPT))"),
            Item::Raw(Reason::GlibcMacro, "# define strstr(HAYSTACK, NEEDLE) __glibc_const_generic (HAYSTACK, const char *, strstr (HAYSTACK, NEEDLE))"),
        ] },
    ], ""),
    Item::Raw(Reason::GlibcMacro, "#define strdupa(s) (__extension__ ({ const char *__old = (s); size_t __len = strlen (__old) + 1; char *__new = (char *) __builtin_alloca (__len); (char *) memcpy (__new, __old, __len); }))"),
    Item::Raw(Reason::GlibcMacro, r#"#define strndupa(s, n) (__extension__ ({ const char *__old = (s); size_t __len = strnlen (__old, (n)); char *__new = (char *) __builtin_alloca (__len + 1); __new[__len] = '\0'; (char *) memcpy (__new, __old, __len); }))"#),
];
pub const TRAILER_CHOMP: bool = false;

