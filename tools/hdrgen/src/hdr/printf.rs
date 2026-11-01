use crate::model::*;

pub static HDR: Header = Header {
    path: "printf.h",
    items: &[
        Item::Comment(r#"/* printf.h for the Rust libc (crates/rusty-libc-stdio/src/printf_ext.rs): user-defined printf conversions.
   struct printf_info is glibc's (20 bytes, the same bit order). Handlers are not called by the wide
   printf functions. */"#),
        Item::Guard { name: "_RLIBC_PRINTF_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<stdio.h>"),
            Item::Include("<stddef.h>"),
            Item::Include("<stdarg.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: "struct printf_info ", body: &["", "  int prec;                     /* Precision.  */", "  int width;                    /* Width.  */", "  wchar_t spec;                 /* Format letter.  */", "  unsigned int is_long_double:1;/* L flag.  */", "  unsigned int is_short:1;      /* h flag.  */", "  unsigned int is_long:1;       /* l flag.  */", "  unsigned int alt:1;           /* # flag.  */", "  unsigned int space:1;         /* Space flag.  */", "  unsigned int left:1;          /* - flag.  */", "  unsigned int showsign:1;      /* + flag.  */", "  unsigned int group:1;         /* ' flag.  */", "  unsigned int extra:1;         /* For special use.  */", "  unsigned int is_char:1;       /* hh flag.  */", "  unsigned int wide:1;          /* Nonzero for wide character streams.  */", "  unsigned int i18n:1;          /* I flag.  */", "  unsigned int is_binary128:1;  /* Floating-point argument is ABI-compatible with IEC 60559 binary128.  */", "  unsigned int __pad:3;         /* Unused so far.  */", "  unsigned short int user;      /* Bits for user-installed modifiers.  */", "  wchar_t pad;                  /* Padding character.  */", ""], tail: "" },
            Item::Blank,
            Item::Comment(r#"/* A handler: STREAM to write to, INFO the conversion, ARGS pointers to the arguments the arginfo function asked
   for. Returns the characters written, -1 for an error, or -2 to leave the conversion to the built-in code. */"#),
            Item::Decl("typedef int printf_function (FILE *__stream, const struct printf_info *__info, const void *const *__args);"),
            Item::Blank,
            Item::Comment("/* How many arguments, of which types (PA_* codes), and the size of each user-defined one. -1: not handled. */"),
            Item::Decl("typedef int printf_arginfo_size_function (const struct printf_info *__info, size_t __n, int *__argtypes, int *__size);"),
            Item::Blank,
            Item::Comment("/* The old arginfo function without the size argument. */"),
            Item::Decl("typedef int printf_arginfo_function (const struct printf_info *__info, size_t __n, int *__argtypes);"),
            Item::Blank,
            Item::Comment("/* Fetches a user-defined type from the argument list into MEM. */"),
            Item::Decl("typedef void printf_va_arg_function (void *__mem, va_list *__ap);"),
            Item::Blank,
            Item::Decl(r#"extern int register_printf_specifier (int __spec, printf_function __func, printf_arginfo_size_function __arginfo)
  __attribute__ ((__nothrow__));"#),
            Item::Blank,
            Item::Decl(r#"extern int register_printf_function (int __spec, printf_function __func, printf_arginfo_function __arginfo)
  __attribute__ ((__nothrow__, __deprecated__));"#),
            Item::Blank,
            Item::Comment("/* Register a modifier string; returns the bit it sets in printf_info.user, or -1. */"),
            Item::Decl("extern int register_printf_modifier (const wchar_t *__str) __attribute__ ((__nothrow__, __warn_unused_result__));"),
            Item::Blank,
            Item::Comment("/* Register an argument type fetched from the va_list by FCT; returns its type code (from PA_LAST up), or -1. */"),
            Item::Decl("extern int register_printf_type (printf_va_arg_function __fct) __attribute__ ((__nothrow__, __warn_unused_result__));"),
            Item::Blank,
            Item::Comment("/* The argument types FMT needs: fills at most N of ARGTYPES, returns the number of arguments. */"),
            Item::Decl(r#"extern size_t parse_printf_format (const char *__restrict __fmt, size_t __n, int *__restrict __argtypes)
  __attribute__ ((__nothrow__));"#),
            Item::Blank,
            Item::Comment("/* Codes for the basic types. */"),
            Item::Block { head: "enum ", body: &["", "  PA_INT,                       /* int */", "  PA_CHAR,                      /* int, cast to char */", "  PA_WCHAR,                     /* wide char */", r#"  PA_STRING,                    /* const char *, a '\0'-terminated string */"#, "  PA_WSTRING,                   /* const wchar_t *, wide character string */", "  PA_POINTER,                   /* void * */", "  PA_FLOAT,                     /* float */", "  PA_DOUBLE,                    /* double */", "  PA_LAST", ""], tail: "" },
            Item::Blank,
            Item::Comment("/* Flag bits of a type. */"),
            Item::Consts(&[
                ("PA_FLAG_MASK", V::Hex(0xff00)),
                ("PA_FLAG_LONG_LONG", V::Txt("(1 << 8)")),
                ("PA_FLAG_LONG_DOUBLE", V::Txt("PA_FLAG_LONG_LONG")),
                ("PA_FLAG_LONG", V::Txt("(1 << 9)")),
                ("PA_FLAG_SHORT", V::Txt("(1 << 10)")),
                ("PA_FLAG_PTR", V::Txt("(1 << 11)")),
            ]),
            Item::Blank,
            Item::Comment(r#"/* %b / %B: a floating-point value with the unit of its magnitude (k, m, g ... in powers of 1024; K, M, G ...
   in powers of 1000). Register with register_printf_function ('b', printf_size, printf_size_info). */"#),
            Item::Decl(r#"extern int printf_size (FILE *__restrict __fp, const struct printf_info *__restrict __info, const void *const *__restrict __args)
  __attribute__ ((__nothrow__));"#),
            Item::Blank,
            Item::Decl(r#"extern int printf_size_info (const struct printf_info *__restrict __info, size_t __n, int *__restrict __argtypes)
  __attribute__ ((__nothrow__));"#),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
