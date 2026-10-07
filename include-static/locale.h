#ifndef _RLIBC_LOCALE_H
#define _RLIBC_LOCALE_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LC_CTYPE 0
#define LC_NUMERIC 1
#define LC_TIME 2
#define LC_COLLATE 3
#define LC_MONETARY 4
#define LC_MESSAGES 5
#define LC_ALL 6
#define LC_PAPER 7
#define LC_NAME 8
#define LC_ADDRESS 9
#define LC_TELEPHONE 10
#define LC_MEASUREMENT 11
#define LC_IDENTIFICATION 12

#define LC_CTYPE_MASK (1 << LC_CTYPE)
#define LC_NUMERIC_MASK (1 << LC_NUMERIC)
#define LC_TIME_MASK (1 << LC_TIME)
#define LC_COLLATE_MASK (1 << LC_COLLATE)
#define LC_MONETARY_MASK (1 << LC_MONETARY)
#define LC_MESSAGES_MASK (1 << LC_MESSAGES)
#define LC_PAPER_MASK (1 << LC_PAPER)
#define LC_NAME_MASK (1 << LC_NAME)
#define LC_ADDRESS_MASK (1 << LC_ADDRESS)
#define LC_TELEPHONE_MASK (1 << LC_TELEPHONE)
#define LC_MEASUREMENT_MASK (1 << LC_MEASUREMENT)
#define LC_IDENTIFICATION_MASK (1 << LC_IDENTIFICATION)
#define LC_ALL_MASK (LC_CTYPE_MASK | LC_NUMERIC_MASK | LC_TIME_MASK | LC_COLLATE_MASK | LC_MONETARY_MASK | LC_MESSAGES_MASK \
                     | LC_PAPER_MASK | LC_NAME_MASK | LC_ADDRESS_MASK | LC_TELEPHONE_MASK | LC_MEASUREMENT_MASK | LC_IDENTIFICATION_MASK)

#ifndef NULL
# define NULL ((void *) 0)
#endif

struct lconv
{
  char *decimal_point;
  char *thousands_sep;
  char *grouping;
  char *int_curr_symbol;
  char *currency_symbol;
  char *mon_decimal_point;
  char *mon_thousands_sep;
  char *mon_grouping;
  char *positive_sign;
  char *negative_sign;
  char int_frac_digits;
  char frac_digits;
  char p_cs_precedes;
  char p_sep_by_space;
  char n_cs_precedes;
  char n_sep_by_space;
  char p_sign_posn;
  char n_sign_posn;
  char int_p_cs_precedes;
  char int_p_sep_by_space;
  char int_n_cs_precedes;
  char int_n_sep_by_space;
  char int_p_sign_posn;
  char int_n_sign_posn;
};

#ifndef _RLIBC_LOCALE_STRUCT
# define _RLIBC_LOCALE_STRUCT 1
struct __locale_data;
struct __locale_struct
{
  struct __locale_data *__locales[13];
  const unsigned short int *__ctype_b;
  const int *__ctype_tolower;
  const int *__ctype_toupper;
  const char *__names[13];
};
#endif

#if !defined _BITS_TYPES_LOCALE_T_H && !defined _RLIBC_LOCALE_T
# define _BITS_TYPES_LOCALE_T_H 1
# define _RLIBC_LOCALE_T
typedef struct __locale_struct *__locale_t;
typedef __locale_t locale_t;
#endif

#define LC_GLOBAL_LOCALE ((locale_t) -1L)

extern char *setlocale (int __category, const char *__locale) __attribute__ ((__nothrow__));
extern struct lconv *localeconv (void) __attribute__ ((__nothrow__));
extern locale_t newlocale (int __category_mask, const char *__locale, locale_t __base) __attribute__ ((__nothrow__));
extern locale_t duplocale (locale_t __dataset) __attribute__ ((__nothrow__));
extern void freelocale (locale_t __dataset) __attribute__ ((__nothrow__));
extern locale_t uselocale (locale_t __dataset) __attribute__ ((__nothrow__));

#ifdef __cplusplus
}
#endif

#endif
