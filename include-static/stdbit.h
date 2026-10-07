#ifndef _RLIBC_STDBIT_H
#define _RLIBC_STDBIT_H 1

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define __STDC_VERSION_STDBIT_H__ 202311L
#define __STDC_ENDIAN_LITTLE__ 1234
#define __STDC_ENDIAN_BIG__ 4321
#define __STDC_ENDIAN_NATIVE__ 1234

#ifdef __cplusplus
extern "C" {
#endif

extern unsigned int stdc_leading_zeros_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_leading_zeros_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_leading_zeros_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_leading_zeros_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_leading_zeros_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_leading_ones_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_leading_ones_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_leading_ones_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_leading_ones_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_leading_ones_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_trailing_zeros_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_trailing_zeros_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_trailing_zeros_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_trailing_zeros_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_trailing_zeros_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_trailing_ones_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_trailing_ones_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_trailing_ones_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_trailing_ones_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_trailing_ones_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_first_leading_zero_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_leading_zero_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_leading_zero_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_leading_zero_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_leading_zero_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_first_leading_one_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_leading_one_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_leading_one_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_leading_one_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_leading_one_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_first_trailing_zero_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_trailing_zero_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_trailing_zero_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_trailing_zero_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_trailing_zero_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_first_trailing_one_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_trailing_one_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_trailing_one_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_trailing_one_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_first_trailing_one_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_count_zeros_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_count_zeros_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_count_zeros_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_count_zeros_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_count_zeros_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_count_ones_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_count_ones_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_count_ones_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_count_ones_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_count_ones_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern bool stdc_has_single_bit_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern bool stdc_has_single_bit_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern bool stdc_has_single_bit_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern bool stdc_has_single_bit_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern bool stdc_has_single_bit_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned int stdc_bit_width_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_bit_width_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_bit_width_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_bit_width_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_bit_width_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned char stdc_bit_floor_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned short stdc_bit_floor_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_bit_floor_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned long stdc_bit_floor_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned long long stdc_bit_floor_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

extern unsigned char stdc_bit_ceil_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));
extern unsigned short stdc_bit_ceil_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));
extern unsigned int stdc_bit_ceil_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));
extern unsigned long stdc_bit_ceil_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));
extern unsigned long long stdc_bit_ceil_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));

#ifdef __cplusplus
}
#endif

#if defined __has_builtin && __has_builtin (__builtin_stdc_leading_zeros)
# define stdc_leading_zeros(x) (__builtin_stdc_leading_zeros (x))
#else
#define stdc_leading_zeros(x) _Generic ((x), unsigned char: stdc_leading_zeros_uc, unsigned short: stdc_leading_zeros_us, unsigned int: stdc_leading_zeros_ui, unsigned long: stdc_leading_zeros_ul, unsigned long long: stdc_leading_zeros_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_leading_ones)
# define stdc_leading_ones(x) (__builtin_stdc_leading_ones (x))
#else
#define stdc_leading_ones(x) _Generic ((x), unsigned char: stdc_leading_ones_uc, unsigned short: stdc_leading_ones_us, unsigned int: stdc_leading_ones_ui, unsigned long: stdc_leading_ones_ul, unsigned long long: stdc_leading_ones_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_trailing_zeros)
# define stdc_trailing_zeros(x) (__builtin_stdc_trailing_zeros (x))
#else
#define stdc_trailing_zeros(x) _Generic ((x), unsigned char: stdc_trailing_zeros_uc, unsigned short: stdc_trailing_zeros_us, unsigned int: stdc_trailing_zeros_ui, unsigned long: stdc_trailing_zeros_ul, unsigned long long: stdc_trailing_zeros_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_trailing_ones)
# define stdc_trailing_ones(x) (__builtin_stdc_trailing_ones (x))
#else
#define stdc_trailing_ones(x) _Generic ((x), unsigned char: stdc_trailing_ones_uc, unsigned short: stdc_trailing_ones_us, unsigned int: stdc_trailing_ones_ui, unsigned long: stdc_trailing_ones_ul, unsigned long long: stdc_trailing_ones_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_first_leading_zero)
# define stdc_first_leading_zero(x) (__builtin_stdc_first_leading_zero (x))
#else
#define stdc_first_leading_zero(x) _Generic ((x), unsigned char: stdc_first_leading_zero_uc, unsigned short: stdc_first_leading_zero_us, unsigned int: stdc_first_leading_zero_ui, unsigned long: stdc_first_leading_zero_ul, unsigned long long: stdc_first_leading_zero_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_first_leading_one)
# define stdc_first_leading_one(x) (__builtin_stdc_first_leading_one (x))
#else
#define stdc_first_leading_one(x) _Generic ((x), unsigned char: stdc_first_leading_one_uc, unsigned short: stdc_first_leading_one_us, unsigned int: stdc_first_leading_one_ui, unsigned long: stdc_first_leading_one_ul, unsigned long long: stdc_first_leading_one_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_first_trailing_zero)
# define stdc_first_trailing_zero(x) (__builtin_stdc_first_trailing_zero (x))
#else
#define stdc_first_trailing_zero(x) _Generic ((x), unsigned char: stdc_first_trailing_zero_uc, unsigned short: stdc_first_trailing_zero_us, unsigned int: stdc_first_trailing_zero_ui, unsigned long: stdc_first_trailing_zero_ul, unsigned long long: stdc_first_trailing_zero_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_first_trailing_one)
# define stdc_first_trailing_one(x) (__builtin_stdc_first_trailing_one (x))
#else
#define stdc_first_trailing_one(x) _Generic ((x), unsigned char: stdc_first_trailing_one_uc, unsigned short: stdc_first_trailing_one_us, unsigned int: stdc_first_trailing_one_ui, unsigned long: stdc_first_trailing_one_ul, unsigned long long: stdc_first_trailing_one_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_count_zeros)
# define stdc_count_zeros(x) (__builtin_stdc_count_zeros (x))
#else
#define stdc_count_zeros(x) _Generic ((x), unsigned char: stdc_count_zeros_uc, unsigned short: stdc_count_zeros_us, unsigned int: stdc_count_zeros_ui, unsigned long: stdc_count_zeros_ul, unsigned long long: stdc_count_zeros_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_count_ones)
# define stdc_count_ones(x) (__builtin_stdc_count_ones (x))
#else
#define stdc_count_ones(x) _Generic ((x), unsigned char: stdc_count_ones_uc, unsigned short: stdc_count_ones_us, unsigned int: stdc_count_ones_ui, unsigned long: stdc_count_ones_ul, unsigned long long: stdc_count_ones_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_has_single_bit)
# define stdc_has_single_bit(x) (__builtin_stdc_has_single_bit (x))
#else
#define stdc_has_single_bit(x) _Generic ((x), unsigned char: stdc_has_single_bit_uc, unsigned short: stdc_has_single_bit_us, unsigned int: stdc_has_single_bit_ui, unsigned long: stdc_has_single_bit_ul, unsigned long long: stdc_has_single_bit_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_bit_width)
# define stdc_bit_width(x) (__builtin_stdc_bit_width (x))
#else
#define stdc_bit_width(x) _Generic ((x), unsigned char: stdc_bit_width_uc, unsigned short: stdc_bit_width_us, unsigned int: stdc_bit_width_ui, unsigned long: stdc_bit_width_ul, unsigned long long: stdc_bit_width_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_bit_floor)
# define stdc_bit_floor(x) (__builtin_stdc_bit_floor (x))
#else
#define stdc_bit_floor(x) _Generic ((x), unsigned char: stdc_bit_floor_uc, unsigned short: stdc_bit_floor_us, unsigned int: stdc_bit_floor_ui, unsigned long: stdc_bit_floor_ul, unsigned long long: stdc_bit_floor_ull) (x)
#endif
#if defined __has_builtin && __has_builtin (__builtin_stdc_bit_ceil)
# define stdc_bit_ceil(x) (__builtin_stdc_bit_ceil (x))
#else
#define stdc_bit_ceil(x) _Generic ((x), unsigned char: stdc_bit_ceil_uc, unsigned short: stdc_bit_ceil_us, unsigned int: stdc_bit_ceil_ui, unsigned long: stdc_bit_ceil_ul, unsigned long long: stdc_bit_ceil_ull) (x)
#endif

#endif
