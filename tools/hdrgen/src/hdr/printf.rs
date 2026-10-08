use crate::model::*;

pub static HDR: Header = Header {
    path: "printf.h",
    items: &[
        Item::Guard { name: "_RLIBC_PRINTF_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<stdio.h>"),
            Item::Include("<stddef.h>"),
            Item::Include("<stdarg.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: "struct printf_info ", body: &["", "  int prec;", "  int width;", "  wchar_t spec;", "  unsigned int is_long_double:1;", "  unsigned int is_short:1;", "  unsigned int is_long:1;", "  unsigned int alt:1;", "  unsigned int space:1;", "  unsigned int left:1;", "  unsigned int showsign:1;", "  unsigned int group:1;", "  unsigned int extra:1;", "  unsigned int is_char:1;", "  unsigned int wide:1;", "  unsigned int i18n:1;", "  unsigned int is_binary128:1;", "  unsigned int __pad:3;", "  unsigned short int user;", "  wchar_t pad;", ""], tail: "" },
            Item::Blank,
            Item::Decl("typedef int printf_function (FILE *__stream, const struct printf_info *__info, const void *const *__args);"),
            Item::Blank,
            Item::Decl("typedef int printf_arginfo_size_function (const struct printf_info *__info, size_t __n, int *__argtypes, int *__size);"),
            Item::Blank,
            Item::Decl("typedef int printf_arginfo_function (const struct printf_info *__info, size_t __n, int *__argtypes);"),
            Item::Blank,
            Item::Decl("typedef void printf_va_arg_function (void *__mem, va_list *__ap);"),
            Item::Blank,
            Item::Decl(r#"extern int register_printf_specifier (int __spec, printf_function __func, printf_arginfo_size_function __arginfo)
  __attribute__ ((__nothrow__));"#),
            Item::Blank,
            Item::Decl(r#"extern int register_printf_function (int __spec, printf_function __func, printf_arginfo_function __arginfo)
  __attribute__ ((__nothrow__, __deprecated__));"#),
            Item::Blank,
            Item::Decl("extern int register_printf_modifier (const wchar_t *__str) __attribute__ ((__nothrow__, __warn_unused_result__));"),
            Item::Blank,
            Item::Decl("extern int register_printf_type (printf_va_arg_function __fct) __attribute__ ((__nothrow__, __warn_unused_result__));"),
            Item::Blank,
            Item::Decl(r#"extern size_t parse_printf_format (const char *__restrict __fmt, size_t __n, int *__restrict __argtypes)
  __attribute__ ((__nothrow__));"#),
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PA_INT,", "  PA_CHAR,", "  PA_WCHAR,", r#"  PA_STRING,"#, "  PA_WSTRING,", "  PA_POINTER,", "  PA_FLOAT,", "  PA_DOUBLE,", "  PA_LAST", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("PA_FLAG_MASK", V::Hex(0xff00)),
                ("PA_FLAG_LONG_LONG", V::Txt("(1 << 8)")),
                ("PA_FLAG_LONG_DOUBLE", V::Txt("PA_FLAG_LONG_LONG")),
                ("PA_FLAG_LONG", V::Txt("(1 << 9)")),
                ("PA_FLAG_SHORT", V::Txt("(1 << 10)")),
                ("PA_FLAG_PTR", V::Txt("(1 << 11)")),
            ]),
            Item::Blank,
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
