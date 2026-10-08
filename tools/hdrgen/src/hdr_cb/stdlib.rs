use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("EXIT_FAILURE", V::Dec(1)),
        ("EXIT_SUCCESS", V::Dec(0)),
        ("RAND_MAX", V::Dec(2147483647)),
        ("MB_CUR_MAX", V::Txt("(__ctype_get_mb_cur_max ())")),
    ]),
    Item::Blank,
    Item::Gate(&[
        Branch { head: "ifdef __USE_MISC", items: &[
            Item::Include("<sys/types.h>"),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "if (defined __USE_XOPEN || defined __USE_XOPEN2K8) && !defined _RLIBC_SYS_WAIT_H", items: &[
            Item::Include("<bits/waitflags.h>"),
            Item::Include("<bits/waitstatus.h>"),
        ] },
    ], ""),
    Item::Blank,
    Item::Gate(&[
        Branch { head: "ifndef __STRICT_ANSI__", items: &[
            Item::Include("<alloca.h>"),
        ] },
    ], ""),
    Item::Blank,
    Item::Gate(&[
        Branch { head: "if __GLIBC_USE (C23_STRTOL)", items: &[
            Item::Raw(Reason::GlibcMacro, r#"# define __RLIBC_C23(n) __asm__("__isoc23_" #n)"#),
        ] },
        Branch { head: "else", items: &[
            Item::Raw(Reason::GlibcMacro, "# define __RLIBC_C23(n)"),
        ] },
    ], ""),
    Item::Decl("long strtol(const char *, char **, int) __RLIBC_C23(strtol);"),
    Item::Decl("long long strtoll(const char *, char **, int) __RLIBC_C23(strtoll);"),
    Item::Decl("unsigned long strtoul(const char *, char **, int) __RLIBC_C23(strtoul);"),
    Item::Decl("unsigned long long strtoull(const char *, char **, int) __RLIBC_C23(strtoull);"),
    Item::Decl("long strtol_l(const char *, char **, int, void *) __RLIBC_C23(strtol_l);"),
    Item::Decl("long long strtoll_l(const char *, char **, int, void *) __RLIBC_C23(strtoll_l);"),
    Item::Decl("unsigned long strtoul_l(const char *, char **, int, void *) __RLIBC_C23(strtoul_l);"),
    Item::Decl("unsigned long long strtoull_l(const char *, char **, int, void *) __RLIBC_C23(strtoull_l);"),
    Item::Decl("long long strtoq(const char *, char **, int) __RLIBC_C23(strtoll);"),
    Item::Decl("unsigned long long strtouq(const char *, char **, int) __RLIBC_C23(strtoull);"),
    Item::Decl("long double strtold(const char *, char **);"),
    Item::Decl("long double strtold_l(const char *, char **, void *);"),
    Item::Decl("float strtof32(const char *, char **);"),
    Item::Decl("double strtof64(const char *, char **);"),
    Item::Decl("double strtof32x(const char *, char **);"),
    Item::Decl("float strtof32_l(const char *, char **, void *);"),
    Item::Decl("double strtof64_l(const char *, char **, void *);"),
    Item::Decl("double strtof32x_l(const char *, char **, void *);"),
    Item::Decl("long double strtof64x(const char *, char **);"),
    Item::Decl("char *qecvt(long double, int, int *, int *);"),
    Item::Decl("char *qfcvt(long double, int, int *, int *);"),
    Item::Decl("char *qgcvt(long double, int, char *);"),
    Item::Decl("int qecvt_r(long double, int, int *, int *, char *, size_t);"),
    Item::Decl("int qfcvt_r(long double, int, int *, int *, char *, size_t);"),
    Item::Decl("int strfroml(char *, size_t, const char *, long double);"),
    Item::Decl("int strfromf32(char *, size_t, const char *, float);"),
    Item::Decl("int strfromf64(char *, size_t, const char *, double);"),
    Item::Decl("int strfromf32x(char *, size_t, const char *, double);"),
    Item::Decl("int strfromf64x(char *, size_t, const char *, long double);"),
    Item::Decl("long double strtof64x_l(const char *, char **, void *);"),
    Item::Decl("_Float128 strtof128(const char *, char **);"),
    Item::Decl("_Float128 strtof128_l(const char *, char **, void *);"),
    Item::Decl("int strfromf128(char *, size_t, const char *, _Float128);"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

pub static TRAILER: &[Item] = &[
    Item::Gate(&[
        Branch { head: "if __GLIBC_USE (ISOC23) && defined __glibc_const_generic && !defined _LIBC", items: &[
            Item::Raw(Reason::GlibcMacro, "# define bsearch(KEY, BASE, NMEMB, SIZE, COMPAR) __glibc_const_generic (BASE, const void *, bsearch (KEY, BASE, NMEMB, SIZE, COMPAR))"),
        ] },
    ], ""),
];
pub const TRAILER_CHOMP: bool = false;

