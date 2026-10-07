#ifndef _RLIBC_PRINTF_H
#define _RLIBC_PRINTF_H 1

#include <bits/rlibc-features.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

struct printf_info {
  int prec;
  int width;
  wchar_t spec;
  unsigned int is_long_double:1;
  unsigned int is_short:1;
  unsigned int is_long:1;
  unsigned int alt:1;
  unsigned int space:1;
  unsigned int left:1;
  unsigned int showsign:1;
  unsigned int group:1;
  unsigned int extra:1;
  unsigned int is_char:1;
  unsigned int wide:1;
  unsigned int i18n:1;
  unsigned int is_binary128:1;
  unsigned int __pad:3;
  unsigned short int user;
  wchar_t pad;
};

typedef int printf_function (FILE *__stream, const struct printf_info *__info, const void *const *__args);

typedef int printf_arginfo_size_function (const struct printf_info *__info, size_t __n, int *__argtypes, int *__size);

typedef int printf_arginfo_function (const struct printf_info *__info, size_t __n, int *__argtypes);

typedef void printf_va_arg_function (void *__mem, va_list *__ap);

extern int register_printf_specifier (int __spec, printf_function __func, printf_arginfo_size_function __arginfo)
  __attribute__ ((__nothrow__));

extern int register_printf_function (int __spec, printf_function __func, printf_arginfo_function __arginfo)
  __attribute__ ((__nothrow__, __deprecated__));

extern int register_printf_modifier (const wchar_t *__str) __attribute__ ((__nothrow__, __warn_unused_result__));

extern int register_printf_type (printf_va_arg_function __fct) __attribute__ ((__nothrow__, __warn_unused_result__));

extern size_t parse_printf_format (const char *__restrict __fmt, size_t __n, int *__restrict __argtypes)
  __attribute__ ((__nothrow__));

enum {
  PA_INT,
  PA_CHAR,
  PA_WCHAR,
  PA_STRING,
  PA_WSTRING,
  PA_POINTER,
  PA_FLOAT,
  PA_DOUBLE,
  PA_LAST
};

#define PA_FLAG_MASK 0xff00
#define PA_FLAG_LONG_LONG (1 << 8)
#define PA_FLAG_LONG_DOUBLE PA_FLAG_LONG_LONG
#define PA_FLAG_LONG (1 << 9)
#define PA_FLAG_SHORT (1 << 10)
#define PA_FLAG_PTR (1 << 11)

extern int printf_size (FILE *__restrict __fp, const struct printf_info *__restrict __info, const void *const *__restrict __args)
  __attribute__ ((__nothrow__));

extern int printf_size_info (const struct printf_info *__restrict __info, size_t __n, int *__restrict __argtypes)
  __attribute__ ((__nothrow__));

#ifdef __cplusplus
}
#endif

#endif
