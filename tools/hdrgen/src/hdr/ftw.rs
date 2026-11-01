use crate::model::*;

pub static HDR: Header = Header {
    path: "ftw.h",
    items: &[
        Item::Comment(r#"/* ftw.h for the Rust libc (crates/rusty-libc-extra/src/ftw.rs): file tree walks, ftw and nftw. The *64 names
   are the same functions: on x86-64 struct stat64 is struct stat. */"#),
        Item::Guard { name: "_RLIBC_FTW_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<sys/stat.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Comment("/* Values for the flag argument of the user function. */"),
            Item::Block { head: "enum ", body: &["", "  FTW_F,                        /* regular file */", "#define FTW_F FTW_F", "  FTW_D,                        /* directory */", "#define FTW_D FTW_D", "  FTW_DNR,                      /* unreadable directory */", "#define FTW_DNR FTW_DNR", "  FTW_NS,                       /* unstatable file */", "#define FTW_NS FTW_NS", "#if defined __RLIBC_USE_MISC || defined __RLIBC_USE_XOPEN", "  FTW_SL,                       /* symbolic link */", "# define FTW_SL FTW_SL", "#endif", "#ifdef __RLIBC_USE_XOPEN", "  /* only passed from nftw */", "  FTW_DP,                       /* directory, all subdirectories have been visited */", "# define FTW_DP FTW_DP", "  FTW_SLN                       /* symbolic link naming a non-existing file */", "# define FTW_SLN FTW_SLN", "#endif", ""], tail: "" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_XOPEN", items: &[
                    Item::Comment("/* Flags for the fourth argument of nftw. */"),
                    Item::Block { head: "enum ", body: &["", "  FTW_PHYS = 1,                 /* physical walk, do not follow symbolic links */", "# define FTW_PHYS FTW_PHYS", "  FTW_MOUNT = 2,                /* stay on the file system of the starting point */", "# define FTW_MOUNT FTW_MOUNT", "  FTW_CHDIR = 4,                /* change into each directory while processing it */", "# define FTW_CHDIR FTW_CHDIR", "  FTW_DEPTH = 8                 /* report a directory after its entries */", "# define FTW_DEPTH FTW_DEPTH", "# ifdef __RLIBC_USE_GNU", "  ,", "  FTW_ACTIONRETVAL = 16         /* the callback returns FTW_* values instead of zero or non-zero */", "#  define FTW_ACTIONRETVAL FTW_ACTIONRETVAL", "# endif", ""], tail: "" },
                    Item::Blank,
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_USE_GNU", items: &[
                            Item::Comment("/* Return values of the callback with FTW_ACTIONRETVAL. */"),
                            Item::Block { head: "enum ", body: &["", "  FTW_CONTINUE = 0,", "# define FTW_CONTINUE FTW_CONTINUE", "  FTW_STOP = 1,", "# define FTW_STOP FTW_STOP", "  FTW_SKIP_SUBTREE = 2,", "# define FTW_SKIP_SUBTREE FTW_SKIP_SUBTREE", "  FTW_SKIP_SIBLINGS = 3", "# define FTW_SKIP_SIBLINGS FTW_SKIP_SIBLINGS", ""], tail: "" },
                        ] },
                    ], ""),
                    Item::Blank,
                    Item::Comment("/* Fourth argument of the nftw callback. */"),
                    Item::Block { head: "struct FTW ", body: &["", "  int base;", "  int level;", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::Decl("typedef int (*__ftw_func_t) (const char *__filename, const struct stat *__status, int __flag);"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_LF64", items: &[
                    Item::Decl("typedef int (*__ftw64_func_t) (const char *__filename, const struct stat64 *__status, int __flag);"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_XOPEN", items: &[
                    Item::Decl("typedef int (*__nftw_func_t) (const char *__filename, const struct stat *__status, int __flag, struct FTW *__info);"),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_USE_LF64", items: &[
                            Item::Decl("typedef int (*__nftw64_func_t) (const char *__filename, const struct stat64 *__status, int __flag, struct FTW *__info);"),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::Decl("extern int ftw (const char *__dir, __ftw_func_t __func, int __descriptors);"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_LF64", items: &[
                    Item::Decl("extern int ftw64 (const char *__dir, __ftw64_func_t __func, int __descriptors);"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_XOPEN", items: &[
                    Item::Decl("extern int nftw (const char *__dir, __nftw_func_t __func, int __descriptors, int __flag);"),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_USE_LF64", items: &[
                            Item::Decl("extern int nftw64 (const char *__dir, __nftw64_func_t __func, int __descriptors, int __flag);"),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
