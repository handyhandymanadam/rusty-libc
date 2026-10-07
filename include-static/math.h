#ifndef _RLIBC_MATH_H
#define _RLIBC_MATH_H 1

#if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || defined _XOPEN_SOURCE || !defined __STRICT_ANSI__
# ifndef __RLIBC_MATH_MISC
#  define __RLIBC_MATH_MISC 1
# endif
#endif
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
#if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_TYPES_EXT__
# ifndef __RLIBC_MATH_FLOATN
#  define __RLIBC_MATH_FLOATN 1
# endif
#endif

#include <bits/rlibc-mathcalls.h>
#include <bits/rlibc-mathaliases.h>
#include <bits/rlibc-mathldcalls.h>
#include <bits/rlibc-mathquadcalls.h>

#define HUGE_VAL (__builtin_huge_val ())
#define HUGE_VALF (__builtin_huge_valf ())
#define HUGE_VALL (__builtin_huge_vall ())
#ifdef __RLIBC_MATH_FLOATN
# define HUGE_VAL_F32 (__builtin_huge_valf32 ())
# define HUGE_VAL_F64 (__builtin_huge_valf64 ())
# define HUGE_VAL_F32X (__builtin_huge_valf32x ())
# define HUGE_VAL_F64X (__builtin_huge_valf64x ())
# define HUGE_VAL_F128 (__builtin_huge_valf128 ())
# define SNANF128 (__builtin_nansf128 (""))
#endif
#define INFINITY (__builtin_inff ())
#define NAN (__builtin_nanf (""))
#ifdef __RLIBC_MATH_EXT
# define SNANF (__builtin_nansf (""))
# define SNAN (__builtin_nans (""))
# define SNANL (__builtin_nansl (""))
#endif
#if defined __RLIBC_MATH_GNU && defined __RLIBC_MATH_FLOATN
# define SNANF32 (__builtin_nansf32 (""))
# define SNANF64 (__builtin_nansf64 (""))
# define SNANF32X (__builtin_nansf32x (""))
# define SNANF64X (__builtin_nansf64x (""))
#endif

#if defined __FLT_EVAL_METHOD__ && __FLT_EVAL_METHOD__ == 2
typedef long double float_t;
typedef long double double_t;
#elif defined __FLT_EVAL_METHOD__ && __FLT_EVAL_METHOD__ == 1
typedef double float_t;
typedef double double_t;
#else
typedef float float_t;
typedef double double_t;
#endif
#if defined __RLIBC_MATH_FLOATN || defined __RLIBC_MATH_EXT
typedef long double long_double_t;
#endif
#ifdef __RLIBC_MATH_FLOATN
# if defined __FLT_EVAL_METHOD__ && __FLT_EVAL_METHOD__ == 2
typedef long double _Float32_t;
typedef long double _Float64_t;
typedef long double _Float32x_t;
typedef long double _Float64x_t;
# elif defined __FLT_EVAL_METHOD__ && __FLT_EVAL_METHOD__ == 1
typedef double _Float32_t;
typedef _Float64 _Float64_t;
typedef double _Float32x_t;
typedef _Float64x _Float64x_t;
# else
typedef _Float32 _Float32_t;
typedef _Float64 _Float64_t;
typedef _Float32x _Float32x_t;
typedef _Float64x _Float64x_t;
# endif
typedef _Float128 _Float128_t;
#endif

#define FP_ILOGB0 (-2147483647 - 1)
#define FP_ILOGBNAN (-2147483647 - 1)
#ifdef __RLIBC_MATH_EXT
# define FP_LLOGB0 (-0x7fffffffffffffffL - 1)
# define FP_LLOGBNAN (-0x7fffffffffffffffL - 1)
#endif

#define FP_NAN 0
#define FP_INFINITE 1
#define FP_ZERO 2
#define FP_SUBNORMAL 3
#define FP_NORMAL 4

#ifdef __FP_FAST_FMA
# define FP_FAST_FMA 1
#endif
#ifdef __FP_FAST_FMAF
# define FP_FAST_FMAF 1
#endif

#define MATH_ERRNO 1
#define MATH_ERREXCEPT 2
#ifdef __FAST_MATH__
# define math_errhandling 0
#else
# define math_errhandling (MATH_ERRNO | MATH_ERREXCEPT)
#endif

#define fpclassify(x) __builtin_fpclassify (FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, x)
#define signbit(x) __builtin_signbit (x)
#define isfinite(x) __builtin_isfinite (x)
#define isnormal(x) __builtin_isnormal (x)
#define isnan(x) __builtin_isnan (x)
#define isinf(x) __builtin_isinf_sign (x)
#define isgreater(x, y) __builtin_isgreater (x, y)
#define isgreaterequal(x, y) __builtin_isgreaterequal (x, y)
#define isless(x, y) __builtin_isless (x, y)
#define islessequal(x, y) __builtin_islessequal (x, y)
#define islessgreater(x, y) __builtin_islessgreater (x, y)
#define isunordered(x, y) __builtin_isunordered (x, y)
#ifdef __RLIBC_MATH_EXT
# define iszero(x) (fpclassify (x) == FP_ZERO)
# define issubnormal(x) (fpclassify (x) == FP_SUBNORMAL)
# define iscanonical(x) _Generic ((x), long double: __iscanonicall (x), default: 1)
# ifdef __RLIBC_MATH_FLOATN
#  define issignaling(x) _Generic ((x), float: __issignalingf, double: __issignaling, long double: __issignalingl, \
                                   _Float32: __issignalingf, _Float64: __issignaling, _Float32x: __issignaling, \
                                   _Float64x: __issignalingl, _Float128: __issignalingf128) (x)
#  define iseqsig(x, y) _Generic ((x) + (y), float: __iseqsigf, double: __iseqsig, long double: __iseqsigl, \
                                  _Float32: __iseqsigf, _Float64: __iseqsig, _Float32x: __iseqsig, \
                                  _Float64x: __iseqsigl, _Float128: __iseqsigf128) ((x), (y))
# else
#  define issignaling(x) _Generic ((x), float: __issignalingf, double: __issignaling, long double: __issignalingl) (x)
#  define iseqsig(x, y) _Generic ((x) + (y), float: __iseqsigf, double: __iseqsig, long double: __iseqsigl) ((x), (y))
# endif
#endif

#if defined __RLIBC_MATH_MISC || defined _XOPEN_SOURCE
# define M_E 2.7182818284590452354
# define M_LOG2E 1.4426950408889634074
# define M_LOG10E 0.43429448190325182765
# define M_LN2 0.69314718055994530942
# define M_LN10 2.30258509299404568402
# define M_PI 3.14159265358979323846
# define M_PI_2 1.57079632679489661923
# define M_PI_4 0.78539816339744830962
# define M_1_PI 0.31830988618379067154
# define M_2_PI 0.63661977236758134308
# define M_2_SQRTPI 1.12837916709551257390
# define M_SQRT2 1.41421356237309504880
# define M_SQRT1_2 0.70710678118654752440
# define MAXFLOAT 3.40282347e+38F
#endif
#ifdef __RLIBC_MATH_GNU
# define M_El 2.718281828459045235360287471352662498L
# define M_LOG2El 1.442695040888963407359924681001892137L
# define M_LOG10El 0.434294481903251827651128918916605082L
# define M_LN2l 0.693147180559945309417232121458176568L
# define M_LN10l 2.302585092994045684017991454684364208L
# define M_PIl 3.141592653589793238462643383279502884L
# define M_PI_2l 1.570796326794896619231321691639751442L
# define M_PI_4l 0.785398163397448309615660845819875721L
# define M_1_PIl 0.318309886183790671537767526745028724L
# define M_2_PIl 0.636619772367581343075535053490057448L
# define M_2_SQRTPIl 1.128379167095512573896158903121545172L
# define M_SQRT2l 1.414213562373095048801688724209698079L
# define M_SQRT1_2l 0.707106781186547524400844362104849039L
# define M_Ef 2.7182818284590452354f
# define M_LOG2Ef 1.4426950408889634074f
# define M_LOG10Ef 0.43429448190325182765f
# define M_LN2f 0.69314718055994530942f
# define M_LN10f 2.30258509299404568402f
# define M_PIf 3.14159265358979323846f
# define M_PI_2f 1.57079632679489661923f
# define M_PI_4f 0.78539816339744830962f
# define M_1_PIf 0.31830988618379067154f
# define M_2_PIf 0.63661977236758134308f
# define M_2_SQRTPIf 1.12837916709551257390f
# define M_SQRT2f 1.41421356237309504880f
# define M_SQRT1_2f 0.70710678118654752440f
# ifdef __RLIBC_MATH_FLOATN
#  include <bits/floatn.h>
#  define M_Ef128 2.718281828459045235360287471352662498f128
#  define M_LOG2Ef128 1.442695040888963407359924681001892137f128
#  define M_LOG10Ef128 0.434294481903251827651128918916605082f128
#  define M_LN2f128 0.693147180559945309417232121458176568f128
#  define M_LN10f128 2.302585092994045684017991454684364208f128
#  define M_PIf128 3.141592653589793238462643383279502884f128
#  define M_PI_2f128 1.570796326794896619231321691639751442f128
#  define M_PI_4f128 0.785398163397448309615660845819875721f128
#  define M_1_PIf128 0.318309886183790671537767526745028724f128
#  define M_2_PIf128 0.636619772367581343075535053490057448f128
#  define M_2_SQRTPIf128 1.128379167095512573896158903121545172f128
#  define M_SQRT2f128 1.414213562373095048801688724209698079f128
#  define M_SQRT1_2f128 0.707106781186547524400844362104849039f128
#  define M_Ef32 2.718281828459045235360287471352662498f32
#  define M_LOG2Ef32 1.442695040888963407359924681001892137f32
#  define M_LOG10Ef32 0.434294481903251827651128918916605082f32
#  define M_LN2f32 0.693147180559945309417232121458176568f32
#  define M_LN10f32 2.302585092994045684017991454684364208f32
#  define M_PIf32 3.141592653589793238462643383279502884f32
#  define M_PI_2f32 1.570796326794896619231321691639751442f32
#  define M_PI_4f32 0.785398163397448309615660845819875721f32
#  define M_1_PIf32 0.318309886183790671537767526745028724f32
#  define M_2_PIf32 0.636619772367581343075535053490057448f32
#  define M_2_SQRTPIf32 1.128379167095512573896158903121545172f32
#  define M_SQRT2f32 1.414213562373095048801688724209698079f32
#  define M_SQRT1_2f32 0.707106781186547524400844362104849039f32
#  define M_Ef64 2.718281828459045235360287471352662498f64
#  define M_LOG2Ef64 1.442695040888963407359924681001892137f64
#  define M_LOG10Ef64 0.434294481903251827651128918916605082f64
#  define M_LN2f64 0.693147180559945309417232121458176568f64
#  define M_LN10f64 2.302585092994045684017991454684364208f64
#  define M_PIf64 3.141592653589793238462643383279502884f64
#  define M_PI_2f64 1.570796326794896619231321691639751442f64
#  define M_PI_4f64 0.785398163397448309615660845819875721f64
#  define M_1_PIf64 0.318309886183790671537767526745028724f64
#  define M_2_PIf64 0.636619772367581343075535053490057448f64
#  define M_2_SQRTPIf64 1.128379167095512573896158903121545172f64
#  define M_SQRT2f64 1.414213562373095048801688724209698079f64
#  define M_SQRT1_2f64 0.707106781186547524400844362104849039f64
#  define M_Ef32x 2.718281828459045235360287471352662498f32x
#  define M_LOG2Ef32x 1.442695040888963407359924681001892137f32x
#  define M_LOG10Ef32x 0.434294481903251827651128918916605082f32x
#  define M_LN2f32x 0.693147180559945309417232121458176568f32x
#  define M_LN10f32x 2.302585092994045684017991454684364208f32x
#  define M_PIf32x 3.141592653589793238462643383279502884f32x
#  define M_PI_2f32x 1.570796326794896619231321691639751442f32x
#  define M_PI_4f32x 0.785398163397448309615660845819875721f32x
#  define M_1_PIf32x 0.318309886183790671537767526745028724f32x
#  define M_2_PIf32x 0.636619772367581343075535053490057448f32x
#  define M_2_SQRTPIf32x 1.128379167095512573896158903121545172f32x
#  define M_SQRT2f32x 1.414213562373095048801688724209698079f32x
#  define M_SQRT1_2f32x 0.707106781186547524400844362104849039f32x
#  define M_Ef64x 2.718281828459045235360287471352662498f64x
#  define M_LOG2Ef64x 1.442695040888963407359924681001892137f64x
#  define M_LOG10Ef64x 0.434294481903251827651128918916605082f64x
#  define M_LN2f64x 0.693147180559945309417232121458176568f64x
#  define M_LN10f64x 2.302585092994045684017991454684364208f64x
#  define M_PIf64x 3.141592653589793238462643383279502884f64x
#  define M_PI_2f64x 1.570796326794896619231321691639751442f64x
#  define M_PI_4f64x 0.785398163397448309615660845819875721f64x
#  define M_1_PIf64x 0.318309886183790671537767526745028724f64x
#  define M_2_PIf64x 0.636619772367581343075535053490057448f64x
#  define M_2_SQRTPIf64x 1.128379167095512573896158903121545172f64x
#  define M_SQRT2f64x 1.414213562373095048801688724209698079f64x
#  define M_SQRT1_2f64x 0.707106781186547524400844362104849039f64x
# endif
#endif

#endif
