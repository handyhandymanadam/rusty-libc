#ifndef _TGMATH_H
#define _TGMATH_H 1

#include <features.h>
#include <math.h>
#include <complex.h>

#if __GLIBC_USE_ISOC23
# define __STDC_VERSION_TGMATH_H__ 202311L
#endif

#if !defined __GNUC__ || (__GNUC__ < 8)
# error "Unsupported compiler; you cannot use <tgmath.h>"
#endif

#ifdef __RLIBC_MATH_FLOATN
# define __TG_FN_ARGS(X) X ## f32, X ## f64, X ## f32x, X ## f64x,
#else
# define __TG_FN_ARGS(X)
#endif
#define __TGMATH_FUNCS(X) X ## f, X, X ## l, __TG_FN_ARGS (X)
#define __TGMATH_RCFUNCS(F, C) __TGMATH_FUNCS (F) __TGMATH_FUNCS (C)
#define __TGMATH_1(F, X) __builtin_tgmath (__TGMATH_FUNCS (F) (X))
#define __TGMATH_2(F, X, Y) __builtin_tgmath (__TGMATH_FUNCS (F) (X), (Y))
#define __TGMATH_2STD(F, X, Y) __builtin_tgmath (F ## f, F, F ## l, (X), (Y))
#define __TGMATH_3(F, X, Y, Z) __builtin_tgmath (__TGMATH_FUNCS (F) (X), (Y), (Z))
#define __TGMATH_1C(F, C, X) __builtin_tgmath (__TGMATH_RCFUNCS (F, C) (X))
#define __TGMATH_2C(F, C, X, Y) __builtin_tgmath (__TGMATH_RCFUNCS (F, C) (X), (Y))

#define __TGMATH_NARROW_FUNCS_F(X) X, X ## l,
#define __TGMATH_1_NARROW_F(F, X) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F (F) (X))
#define __TGMATH_2_NARROW_F(F, X, Y) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F (F) (X), (Y))
#define __TGMATH_3_NARROW_F(F, X, Y, Z) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F (F) (X), (Y), (Z))
#define __TGMATH_1_NARROW_D(F, X) (F ## l (X))
#define __TGMATH_2_NARROW_D(F, X, Y) (F ## l (X, Y))
#define __TGMATH_3_NARROW_D(F, X, Y, Z) (F ## l (X, Y, Z))

#define __TGMATH_UNARY_REAL_ONLY(Val, Fct) __TGMATH_1 (Fct, (Val))
#define __TGMATH_UNARY_REAL_RET_ONLY(Val, Fct) __TGMATH_1 (Fct, (Val))
#define __TGMATH_BINARY_FIRST_REAL_ONLY(Val1, Val2, Fct) __TGMATH_2 (Fct, (Val1), (Val2))
#define __TGMATH_BINARY_FIRST_REAL_STD_ONLY(Val1, Val2, Fct) __TGMATH_2STD (Fct, (Val1), (Val2))
#define __TGMATH_BINARY_REAL_ONLY(Val1, Val2, Fct) __TGMATH_2 (Fct, (Val1), (Val2))
#define __TGMATH_BINARY_REAL_STD_ONLY(Val1, Val2, Fct) __TGMATH_2STD (Fct, (Val1), (Val2))
#define __TGMATH_TERNARY_FIRST_SECOND_REAL_ONLY(Val1, Val2, Val3, Fct) __TGMATH_3 (Fct, (Val1), (Val2), (Val3))
#define __TGMATH_TERNARY_REAL_ONLY(Val1, Val2, Val3, Fct) __TGMATH_3 (Fct, (Val1), (Val2), (Val3))
#define __TGMATH_TERNARY_FIRST_REAL_ONLY(Val1, Val2, Val3, Fct) __TGMATH_3 (Fct, (Val1), (Val2), (Val3))
#define __TGMATH_UNARY_REAL_IMAG(Val, Fct, Cfct) __TGMATH_1C (Fct, Cfct, (Val))
#define __TGMATH_UNARY_IMAG(Val, Cfct) __TGMATH_1 (Cfct, (Val))
#define __TGMATH_UNARY_REAL_IMAG_RET_REAL(Val, Fct, Cfct) __TGMATH_1C (Fct, Cfct, (Val))
#define __TGMATH_UNARY_REAL_IMAG_RET_REAL_SAME(Val, Cfct) __TGMATH_1 (Cfct, (Val))
#define __TGMATH_BINARY_REAL_IMAG(Val1, Val2, Fct, Cfct) __TGMATH_2C (Fct, Cfct, (Val1), (Val2))

#define acos(Val) __TGMATH_UNARY_REAL_IMAG (Val, acos, cacos)
#define asin(Val) __TGMATH_UNARY_REAL_IMAG (Val, asin, casin)
#define atan(Val) __TGMATH_UNARY_REAL_IMAG (Val, atan, catan)
#define atan2(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, atan2)
#define cos(Val) __TGMATH_UNARY_REAL_IMAG (Val, cos, ccos)
#define sin(Val) __TGMATH_UNARY_REAL_IMAG (Val, sin, csin)
#define tan(Val) __TGMATH_UNARY_REAL_IMAG (Val, tan, ctan)
#ifdef __RLIBC_MATH_EXT
# define acospi(Val) __TGMATH_UNARY_REAL_ONLY (Val, acospi)
# define asinpi(Val) __TGMATH_UNARY_REAL_ONLY (Val, asinpi)
# define atanpi(Val) __TGMATH_UNARY_REAL_ONLY (Val, atanpi)
# define atan2pi(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, atan2pi)
# define cospi(Val) __TGMATH_UNARY_REAL_ONLY (Val, cospi)
# define sinpi(Val) __TGMATH_UNARY_REAL_ONLY (Val, sinpi)
# define tanpi(Val) __TGMATH_UNARY_REAL_ONLY (Val, tanpi)
#endif
#define acosh(Val) __TGMATH_UNARY_REAL_IMAG (Val, acosh, cacosh)
#define asinh(Val) __TGMATH_UNARY_REAL_IMAG (Val, asinh, casinh)
#define atanh(Val) __TGMATH_UNARY_REAL_IMAG (Val, atanh, catanh)
#define cosh(Val) __TGMATH_UNARY_REAL_IMAG (Val, cosh, ccosh)
#define sinh(Val) __TGMATH_UNARY_REAL_IMAG (Val, sinh, csinh)
#define tanh(Val) __TGMATH_UNARY_REAL_IMAG (Val, tanh, ctanh)

#define exp(Val) __TGMATH_UNARY_REAL_IMAG (Val, exp, cexp)
#define frexp(Val1, Val2) __TGMATH_BINARY_FIRST_REAL_ONLY (Val1, Val2, frexp)
#define ldexp(Val1, Val2) __TGMATH_BINARY_FIRST_REAL_ONLY (Val1, Val2, ldexp)
#define log(Val) __TGMATH_UNARY_REAL_IMAG (Val, log, clog)
#ifdef __USE_GNU
# define log10(Val) __TGMATH_UNARY_REAL_IMAG (Val, log10, clog10)
#else
# define log10(Val) __TGMATH_UNARY_REAL_ONLY (Val, log10)
#endif
#define expm1(Val) __TGMATH_UNARY_REAL_ONLY (Val, expm1)
#define log1p(Val) __TGMATH_UNARY_REAL_ONLY (Val, log1p)
#define logb(Val) __TGMATH_UNARY_REAL_ONLY (Val, logb)
#define exp2(Val) __TGMATH_UNARY_REAL_ONLY (Val, exp2)
#define log2(Val) __TGMATH_UNARY_REAL_ONLY (Val, log2)
#ifdef __RLIBC_MATH_EXT
# define exp10(Val) __TGMATH_UNARY_REAL_ONLY (Val, exp10)
# define exp2m1(Val) __TGMATH_UNARY_REAL_ONLY (Val, exp2m1)
# define exp10m1(Val) __TGMATH_UNARY_REAL_ONLY (Val, exp10m1)
# define log2p1(Val) __TGMATH_UNARY_REAL_ONLY (Val, log2p1)
# define log10p1(Val) __TGMATH_UNARY_REAL_ONLY (Val, log10p1)
# define logp1(Val) __TGMATH_UNARY_REAL_ONLY (Val, logp1)
#endif

#define pow(Val1, Val2) __TGMATH_BINARY_REAL_IMAG (Val1, Val2, pow, cpow)
#define sqrt(Val) __TGMATH_UNARY_REAL_IMAG (Val, sqrt, csqrt)
#define hypot(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, hypot)
#define cbrt(Val) __TGMATH_UNARY_REAL_ONLY (Val, cbrt)
#ifdef __RLIBC_MATH_EXT
# define compoundn(Val1, Val2) __TGMATH_BINARY_FIRST_REAL_ONLY (Val1, Val2, compoundn)
# define pown(Val1, Val2) __TGMATH_BINARY_FIRST_REAL_ONLY (Val1, Val2, pown)
# define powr(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, powr)
# define rootn(Val1, Val2) __TGMATH_BINARY_FIRST_REAL_ONLY (Val1, Val2, rootn)
# define rsqrt(Val) __TGMATH_UNARY_REAL_ONLY (Val, rsqrt)
#endif

#define ceil(Val) __TGMATH_UNARY_REAL_ONLY (Val, ceil)
#define fabs(Val) __TGMATH_UNARY_REAL_IMAG_RET_REAL (Val, fabs, cabs)
#define floor(Val) __TGMATH_UNARY_REAL_ONLY (Val, floor)
#define fmod(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmod)
#define nearbyint(Val) __TGMATH_UNARY_REAL_ONLY (Val, nearbyint)
#define round(Val) __TGMATH_UNARY_REAL_ONLY (Val, round)
#define trunc(Val) __TGMATH_UNARY_REAL_ONLY (Val, trunc)
#define remquo(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_SECOND_REAL_ONLY (Val1, Val2, Val3, remquo)
#define lrint(Val) __TGMATH_UNARY_REAL_RET_ONLY (Val, lrint)
#define llrint(Val) __TGMATH_UNARY_REAL_RET_ONLY (Val, llrint)
#define lround(Val) __TGMATH_UNARY_REAL_RET_ONLY (Val, lround)
#define llround(Val) __TGMATH_UNARY_REAL_RET_ONLY (Val, llround)
#define copysign(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, copysign)

#define erf(Val) __TGMATH_UNARY_REAL_ONLY (Val, erf)
#define erfc(Val) __TGMATH_UNARY_REAL_ONLY (Val, erfc)
#define tgamma(Val) __TGMATH_UNARY_REAL_ONLY (Val, tgamma)
#define lgamma(Val) __TGMATH_UNARY_REAL_ONLY (Val, lgamma)
#define rint(Val) __TGMATH_UNARY_REAL_ONLY (Val, rint)
#ifdef __RLIBC_MATH_EXT
# define nextdown(Val) __TGMATH_UNARY_REAL_ONLY (Val, nextdown)
# define nextup(Val) __TGMATH_UNARY_REAL_ONLY (Val, nextup)
#endif
#define nextafter(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, nextafter)
#define nexttoward(Val1, Val2) __TGMATH_BINARY_FIRST_REAL_STD_ONLY (Val1, Val2, nexttoward)
#define remainder(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, remainder)
#ifdef __USE_MISC
# define scalb(Val1, Val2) __TGMATH_BINARY_REAL_STD_ONLY (Val1, Val2, scalb)
#endif
#define scalbn(Val1, Val2) __TGMATH_BINARY_FIRST_REAL_ONLY (Val1, Val2, scalbn)
#define scalbln(Val1, Val2) __TGMATH_BINARY_FIRST_REAL_ONLY (Val1, Val2, scalbln)
#define ilogb(Val) __TGMATH_UNARY_REAL_RET_ONLY (Val, ilogb)
#define fdim(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fdim)
#if __GLIBC_USE_ISOC23 && !defined __USE_GNU
# define fmax(Val1, Val2) __TGMATH_BINARY_REAL_STD_ONLY (Val1, Val2, fmax)
# define fmin(Val1, Val2) __TGMATH_BINARY_REAL_STD_ONLY (Val1, Val2, fmin)
#else
# define fmax(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmax)
# define fmin(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmin)
#endif
#define fma(Val1, Val2, Val3) __TGMATH_TERNARY_REAL_ONLY (Val1, Val2, Val3, fma)
#ifdef __RLIBC_MATH_EXT
# define roundeven(Val) __TGMATH_UNARY_REAL_ONLY (Val, roundeven)
# define fromfp(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_REAL_ONLY (Val1, Val2, Val3, fromfp)
# define ufromfp(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_REAL_ONLY (Val1, Val2, Val3, ufromfp)
# define fromfpx(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_REAL_ONLY (Val1, Val2, Val3, fromfpx)
# define ufromfpx(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_REAL_ONLY (Val1, Val2, Val3, ufromfpx)
# define llogb(Val) __TGMATH_UNARY_REAL_RET_ONLY (Val, llogb)
# define fmaxmag(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmaxmag)
# define fminmag(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fminmag)
#endif
#if __GLIBC_USE_ISOC23
# define fmaximum(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmaximum)
# define fminimum(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fminimum)
# define fmaximum_num(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmaximum_num)
# define fminimum_num(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fminimum_num)
# define fmaximum_mag(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmaximum_mag)
# define fminimum_mag(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fminimum_mag)
# define fmaximum_mag_num(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmaximum_mag_num)
# define fminimum_mag_num(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fminimum_mag_num)
#endif

#define carg(Val) __TGMATH_UNARY_REAL_IMAG_RET_REAL_SAME (Val, carg)
#define conj(Val) __TGMATH_UNARY_IMAG (Val, conj)
#define cproj(Val) __TGMATH_UNARY_IMAG (Val, cproj)
#define cimag(Val) __TGMATH_UNARY_REAL_IMAG_RET_REAL_SAME (Val, cimag)
#define creal(Val) __TGMATH_UNARY_REAL_IMAG_RET_REAL_SAME (Val, creal)

#ifdef __RLIBC_MATH_EXT
# define fadd(Val1, Val2) __TGMATH_2_NARROW_F (fadd, Val1, Val2)
# define dadd(Val1, Val2) __TGMATH_2_NARROW_D (dadd, Val1, Val2)
# define fdiv(Val1, Val2) __TGMATH_2_NARROW_F (fdiv, Val1, Val2)
# define ddiv(Val1, Val2) __TGMATH_2_NARROW_D (ddiv, Val1, Val2)
# define fmul(Val1, Val2) __TGMATH_2_NARROW_F (fmul, Val1, Val2)
# define dmul(Val1, Val2) __TGMATH_2_NARROW_D (dmul, Val1, Val2)
# define fsub(Val1, Val2) __TGMATH_2_NARROW_F (fsub, Val1, Val2)
# define dsub(Val1, Val2) __TGMATH_2_NARROW_D (dsub, Val1, Val2)
# define fsqrt(Val) __TGMATH_1_NARROW_F (fsqrt, Val)
# define dsqrt(Val) __TGMATH_1_NARROW_D (dsqrt, Val)
# define ffma(Val1, Val2, Val3) __TGMATH_3_NARROW_F (ffma, Val1, Val2, Val3)
# define dfma(Val1, Val2, Val3) __TGMATH_3_NARROW_D (dfma, Val1, Val2, Val3)
#endif

#endif
