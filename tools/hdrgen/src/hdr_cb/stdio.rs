use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Gate(&[
        Branch { head: "ifndef __FILE_defined", items: &[
            Item::ConstsFlat(&[
                ("__FILE_defined", V::Dec(1)),
            ]),
            Item::Raw(Reason::Other, "#include <bits/types/struct_FILE.h>"),
            Item::Typedef("struct _IO_FILE", "FILE"),
        ] },
    ], ""),
    Item::Decl("struct obstack;"),
    Item::Blank,
    Item::Consts(&[
        ("EOF", V::Txt("(-1)")),
        ("BUFSIZ", V::Dec(8192)),
        ("SEEK_SET", V::Dec(0)),
        ("SEEK_CUR", V::Dec(1)),
        ("SEEK_END", V::Dec(2)),
        ("_IOFBF", V::Dec(0)),
        ("_IOLBF", V::Dec(1)),
        ("_IONBF", V::Dec(2)),
        ("FILENAME_MAX", V::Dec(4096)),
        ("FOPEN_MAX", V::Dec(16)),
        ("L_tmpnam", V::Dec(20)),
        ("L_cuserid", V::Dec(9)),
        ("TMP_MAX", V::Dec(238328)),
        ("P_tmpdir", V::Txt(r#""/tmp""#)),
    ]),
    Item::Gate(&[
        Branch { head: "if __GLIBC_USE (DEPRECATED_SCANF)", items: &[
            Item::Raw(Reason::GlibcMacro, "# define __RLIBC_SCANF_ASM(n)"),
        ] },
        Branch { head: "elif __GLIBC_USE (C23_STRTOL)", items: &[
            Item::Raw(Reason::GlibcMacro, "# define __RLIBC_SCANF_ASM(n) __asm__(__RLIBC_STR(__isoc23_##n))"),
        ] },
        Branch { head: "else", items: &[
            Item::Raw(Reason::GlibcMacro, "# define __RLIBC_SCANF_ASM(n) __asm__(__RLIBC_STR(__isoc99_##n))"),
        ] },
    ], ""),
    Item::Raw(Reason::GlibcMacro, "#define __RLIBC_STR2(x) #x"),
    Item::Raw(Reason::GlibcMacro, "#define __RLIBC_STR(x) __RLIBC_STR2(x)"),
    Item::Decl("int fscanf(FILE *, const char *, ...) __RLIBC_SCANF_ASM(fscanf);"),
    Item::Decl("int scanf(const char *, ...) __RLIBC_SCANF_ASM(scanf);"),
    Item::Decl("int sscanf(const char *, const char *, ...) __RLIBC_SCANF_ASM(sscanf);"),
    Item::Decl("int vfscanf(FILE *, const char *, va_list) __RLIBC_SCANF_ASM(vfscanf);"),
    Item::Decl("int vscanf(const char *, va_list) __RLIBC_SCANF_ASM(vscanf);"),
    Item::Decl("int vsscanf(const char *, const char *, va_list) __RLIBC_SCANF_ASM(vsscanf);"),
    Item::Blank,
    Item::Decl("int fgetc_unlocked(FILE *);"),
    Item::Decl("int getc_unlocked(FILE *);"),
    Item::Decl("int getchar_unlocked(void);"),
    Item::Decl("int fputc_unlocked(int, FILE *);"),
    Item::Decl("int putc_unlocked(int, FILE *);"),
    Item::Decl("int putchar_unlocked(int);"),
    Item::Decl("char *fgets_unlocked(char *, int, FILE *);"),
    Item::Decl("int fputs_unlocked(const char *, FILE *);"),
    Item::Decl("size_t fread_unlocked(void *, size_t, size_t, FILE *);"),
    Item::Decl("size_t fwrite_unlocked(const void *, size_t, size_t, FILE *);"),
    Item::Decl("int feof_unlocked(FILE *);"),
    Item::Decl("int ferror_unlocked(FILE *);"),
    Item::Decl("void clearerr_unlocked(FILE *);"),
    Item::Decl("int fflush_unlocked(FILE *);"),
    Item::Decl("int fileno_unlocked(FILE *);"),
    Item::Decl("FILE *fopen64(const char *, const char *);"),
    Item::Decl("FILE *freopen64(const char *, const char *, FILE *);"),
    Item::Decl("int fseeko64(FILE *, off_t, int);"),
    Item::Decl("off_t ftello64(FILE *);"),
    Item::Decl("FILE *tmpfile64(void);"),
    Item::Decl("ssize_t __getdelim(char **, size_t *, int, FILE *);"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

pub static TRAILER: &[Item] = &[
    Item::Gate(&[
        Branch { head: "if defined __USE_LARGEFILE64 || defined __USE_FILE_OFFSET64", items: &[
            Item::Typedef("fpos_t", "fpos64_t"),
        ] },
    ], ""),
    Item::Consts(&[
        ("stdin", V::Txt("stdin")),
        ("stdout", V::Txt("stdout")),
        ("stderr", V::Txt("stderr")),
        ("L_ctermid", V::Dec(9)),
    ]),
    Item::Gate(&[
        Branch { head: "if defined __USE_GNU || defined __USE_XOPEN2K24", items: &[
            Item::Consts(&[
                ("SEEK_DATA", V::Dec(3)),
                ("SEEK_HOLE", V::Dec(4)),
            ]),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "ifdef __USE_GNU", items: &[
            Item::Consts(&[
                ("AT_RENAME_NOREPLACE", V::Hex(0x1)),
                ("AT_RENAME_EXCHANGE", V::Hex(0x2)),
                ("AT_RENAME_WHITEOUT", V::Hex(0x4)),
            ]),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "ifdef __USE_GNU", items: &[
            Item::Consts(&[
                ("RENAME_NOREPLACE", V::Txt("(1 << 0)")),
                ("RENAME_EXCHANGE", V::Txt("(1 << 1)")),
                ("RENAME_WHITEOUT", V::Txt("(1 << 2)")),
            ]),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function", items: &[
            Item::Include("<bits/stdio2-decl.h>"),
            Item::Include("<bits/stdio2.h>"),
        ] },
    ], ""),
];
pub const TRAILER_CHOMP: bool = false;

