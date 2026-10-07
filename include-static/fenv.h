#ifndef _RLIBC_FENV_H
#define _RLIBC_FENV_H 1

#ifdef _GNU_SOURCE
# ifndef __RLIBC_MATH_GNU
#  define __RLIBC_MATH_GNU 1
# endif
#endif
#if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_BFP_EXT__ || defined __STDC_WANT_IEC_60559_FUNCS_EXT__ \
    || defined __STDC_WANT_IEC_60559_EXT__ || (defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L)
# ifndef __RLIBC_MATH_EXT
#  define __RLIBC_MATH_EXT 1
# endif
#endif

#define FE_INVALID 0x01
#define __FE_DENORM 0x02
#define FE_DIVBYZERO 0x04
#define FE_OVERFLOW 0x08
#define FE_UNDERFLOW 0x10
#define FE_INEXACT 0x20
#define FE_ALL_EXCEPT (FE_INEXACT | FE_DIVBYZERO | FE_UNDERFLOW | FE_OVERFLOW | FE_INVALID)

#define FE_TONEAREST 0
#define FE_DOWNWARD 0x400
#define FE_UPWARD 0x800
#define FE_TOWARDZERO 0xc00

typedef unsigned short int fexcept_t;

typedef struct {
  unsigned short int __control_word;
  unsigned short int __glibc_reserved1;
  unsigned short int __status_word;
  unsigned short int __glibc_reserved2;
  unsigned short int __tags;
  unsigned short int __glibc_reserved3;
  unsigned int __eip;
  unsigned short int __cs_selector;
  unsigned int __opcode:11;
  unsigned int __glibc_reserved4:5;
  unsigned int __data_offset;
  unsigned short int __data_selector;
  unsigned short int __glibc_reserved5;
  unsigned int __mxcsr;
} fenv_t;

#define FE_DFL_ENV ((const fenv_t *) -1)
#ifdef __RLIBC_MATH_GNU
# define FE_NOMASK_ENV ((const fenv_t *) -2)
#endif

#ifdef __RLIBC_MATH_EXT
typedef struct {
  unsigned short int __control_word;
  unsigned short int __glibc_reserved;
  unsigned int __mxcsr;
} femode_t;
# define FE_DFL_MODE ((const femode_t *) -1L)
#endif

#include <bits/rlibc-fenvcalls.h>

#endif
