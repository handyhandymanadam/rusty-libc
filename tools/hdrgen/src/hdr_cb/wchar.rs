use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("__need_wint_t", V::Txt("")),
    ]),
    Item::Include("<stddef.h>"),
    Item::Undef("__need_wint_t"),
    Item::Gate(&[
        Branch { head: "ifndef ____mbstate_t_defined", items: &[
            Item::ConstsFlat(&[
                ("____mbstate_t_defined", V::Dec(1)),
            ]),
            Item::Block { head: "typedef struct ", body: &[" int __count; union { wint_t __wch; char __wchb[4]; } __value; "], tail: " __mbstate_t" },
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "ifndef __mbstate_t_defined", items: &[
            Item::ConstsFlat(&[
                ("__mbstate_t_defined", V::Dec(1)),
            ]),
            Item::Typedef("__mbstate_t", "mbstate_t"),
        ] },
    ], ""),
    Item::Include("<bits/types/locale_t.h>"),
    Item::Blank,
    Item::Gate(&[
        Branch { head: "ifndef __FILE_defined", items: &[
            Item::ConstsFlat(&[
                ("__FILE_defined", V::Dec(1)),
            ]),
            Item::Raw(Reason::Other, "#include <bits/types/struct_FILE.h>"),
            Item::Typedef("struct _IO_FILE", "FILE"),
        ] },
    ], ""),
    Item::Blank,
    Item::Consts(&[
        ("WEOF", V::Txt("(0xffffffffu)")),
        ("WCHAR_MAX", V::Txt("__WCHAR_MAX__")),
        ("WCHAR_MIN", V::Txt("(-__WCHAR_MAX__ - 1)")),
    ]),
    Item::Blank,
    Item::Gate(&[
        Branch { head: "if __GLIBC_USE (C23_STRTOL)", items: &[
            Item::Raw(Reason::GlibcMacro, r#"# define __RLIBC_C23(n) __asm__("__isoc23_" #n)"#),
            Item::Raw(Reason::GlibcMacro, r#"# define __RLIBC_C23_AS(n) __asm__("__isoc23_" #n)"#),
        ] },
        Branch { head: "else", items: &[
            Item::Raw(Reason::GlibcMacro, "# define __RLIBC_C23(n)"),
            Item::Raw(Reason::GlibcMacro, "# define __RLIBC_C23_AS(n)"),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "if __GLIBC_USE (DEPRECATED_SCANF)", items: &[
            Item::Raw(Reason::GlibcMacro, "# define __RLIBC_WSCANF(n)"),
        ] },
        Branch { head: "elif __GLIBC_USE (C23_STRTOL)", items: &[
            Item::Raw(Reason::GlibcMacro, r#"# define __RLIBC_WSCANF(n) __asm__("__isoc23_" #n)"#),
        ] },
        Branch { head: "else", items: &[
            Item::Raw(Reason::GlibcMacro, r#"# define __RLIBC_WSCANF(n) __asm__("__isoc99_" #n)"#),
        ] },
    ], ""),
    Item::Decl("wint_t fgetwc(FILE *);"),
    Item::Decl("wint_t getwc(FILE *);"),
    Item::Decl("wint_t fgetwc_unlocked(FILE *);"),
    Item::Decl("wint_t getwc_unlocked(FILE *);"),
    Item::Decl("wint_t fputwc(wchar_t, FILE *);"),
    Item::Decl("wint_t putwc(wchar_t, FILE *);"),
    Item::Decl("wint_t fputwc_unlocked(wchar_t, FILE *);"),
    Item::Decl("wint_t putwc_unlocked(wchar_t, FILE *);"),
    Item::Decl("int fwscanf(FILE *, const wchar_t *, ...) __RLIBC_WSCANF(fwscanf);"),
    Item::Decl("int wscanf(const wchar_t *, ...) __RLIBC_WSCANF(wscanf);"),
    Item::Decl("int swscanf(const wchar_t *, const wchar_t *, ...) __RLIBC_WSCANF(swscanf);"),
    Item::Decl("int vfwscanf(FILE *, const wchar_t *, va_list) __RLIBC_WSCANF(vfwscanf);"),
    Item::Decl("int vwscanf(const wchar_t *, va_list) __RLIBC_WSCANF(vwscanf);"),
    Item::Decl("int vswscanf(const wchar_t *, const wchar_t *, va_list) __RLIBC_WSCANF(vswscanf);"),
    Item::Blank,
    Item::Decl("long wcstol(const wchar_t *, wchar_t **, int) __RLIBC_C23(wcstol);"),
    Item::Decl("long wcstol_l(const wchar_t *, wchar_t **, int, locale_t) __RLIBC_C23(wcstol_l);"),
    Item::Decl("long long wcstoll(const wchar_t *, wchar_t **, int) __RLIBC_C23(wcstoll);"),
    Item::Decl("long long wcstoll_l(const wchar_t *, wchar_t **, int, locale_t) __RLIBC_C23(wcstoll_l);"),
    Item::Decl("unsigned long wcstoul(const wchar_t *, wchar_t **, int) __RLIBC_C23(wcstoul);"),
    Item::Decl("unsigned long wcstoul_l(const wchar_t *, wchar_t **, int, locale_t) __RLIBC_C23(wcstoul_l);"),
    Item::Decl("unsigned long long wcstoull(const wchar_t *, wchar_t **, int) __RLIBC_C23(wcstoull);"),
    Item::Decl("unsigned long long wcstoull_l(const wchar_t *, wchar_t **, int, locale_t) __RLIBC_C23(wcstoull_l);"),
    Item::Decl("long long wcstoq(const wchar_t *, wchar_t **, int) __RLIBC_C23_AS(wcstoll);"),
    Item::Decl("unsigned long long wcstouq(const wchar_t *, wchar_t **, int) __RLIBC_C23_AS(wcstoull);"),
    Item::Decl("intmax_t wcstoimax(const wchar_t *, wchar_t **, int) __RLIBC_C23(wcstoimax);"),
    Item::Decl("uintmax_t wcstoumax(const wchar_t *, wchar_t **, int) __RLIBC_C23(wcstoumax);"),
    Item::Decl("long double wcstold(const wchar_t *, wchar_t **);"),
    Item::Decl("long double wcstold_l(const wchar_t *, wchar_t **, locale_t);"),
    Item::Decl("float wcstof32(const wchar_t *, wchar_t **);"),
    Item::Decl("double wcstof64(const wchar_t *, wchar_t **);"),
    Item::Decl("double wcstof32x(const wchar_t *, wchar_t **);"),
    Item::Decl("float wcstof32_l(const wchar_t *, wchar_t **, locale_t);"),
    Item::Decl("double wcstof64_l(const wchar_t *, wchar_t **, locale_t);"),
    Item::Decl("double wcstof32x_l(const wchar_t *, wchar_t **, locale_t);"),
    Item::Decl("long double wcstof64x(const wchar_t *, wchar_t **);"),
    Item::Decl("long double wcstof64x_l(const wchar_t *, wchar_t **, locale_t);"),
    Item::Decl("_Float128 wcstof128(const wchar_t *, wchar_t **);"),
    Item::Decl("_Float128 wcstof128_l(const wchar_t *, wchar_t **, locale_t);"),
    Item::Decl("struct tm;"),
    Item::Decl("size_t wcsftime(wchar_t *, size_t, const wchar_t *, const struct tm *);"),
    Item::Decl("size_t wcsftime_l(wchar_t *, size_t, const wchar_t *, const struct tm *, locale_t);"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

pub static TRAILER: &[Item] = &[
    Item::Gate(&[
        Branch { head: "if __GLIBC_USE (ISOC23) && defined __glibc_const_generic && !defined _LIBC", items: &[
            Item::Raw(Reason::GlibcMacro, "# define wcschr(WCS, WC) __glibc_const_generic (WCS, const wchar_t *, wcschr (WCS, WC))"),
            Item::Raw(Reason::GlibcMacro, "# define wcsrchr(WCS, WC) __glibc_const_generic (WCS, const wchar_t *, wcsrchr (WCS, WC))"),
            Item::Raw(Reason::GlibcMacro, "# define wcspbrk(WCS, ACCEPT) __glibc_const_generic (WCS, const wchar_t *, wcspbrk (WCS, ACCEPT))"),
            Item::Raw(Reason::GlibcMacro, "# define wcsstr(HAYSTACK, NEEDLE) __glibc_const_generic (HAYSTACK, const wchar_t *, wcsstr (HAYSTACK, NEEDLE))"),
            Item::Raw(Reason::GlibcMacro, "# define wmemchr(S, C, N) __glibc_const_generic (S, const wchar_t *, wmemchr (S, C, N))"),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function", items: &[
            Item::Include("<bits/wchar2-decl.h>"),
            Item::Include("<bits/wchar2.h>"),
        ] },
    ], ""),
];
pub const TRAILER_CHOMP: bool = false;

