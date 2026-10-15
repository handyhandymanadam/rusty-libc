use crate::model::*;

pub static HDR: Header = Header {
    path: "tgmath.h",
    items: &[
        Item::Guard { name: "_TGMATH_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Include("<bits/floatn.h>"),
            Item::Include("<math.h>"),
            Item::Include("<complex.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if __GLIBC_USE_ISOC23", items: &[
                    Item::Consts(&[
                        ("__STDC_VERSION_TGMATH_H__", V::Txt("202311L")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Raw(Reason::StdMacro, r#"#if __GNUC_PREREQ (2, 7)
# if __HAVE_FLOAT128X
# error "Unsupported _Float128x type for <tgmath.h>."
# endif
# if ((__HAVE_FLOAT64X && !__HAVE_FLOAT128) || (__HAVE_FLOAT128 && !__HAVE_FLOAT64X))
# error "Unsupported combination of types for <tgmath.h>."
# endif
# define __TGMATH_1_NARROW_D(F, X) (F ## l (X))
# define __TGMATH_2_NARROW_D(F, X, Y) (F ## l (X, Y))
# define __TGMATH_3_NARROW_D(F, X, Y, Z) (F ## l (X, Y, Z))
# define __TGMATH_1_NARROW_F64X(F, X) (F ## f128 (X))
# define __TGMATH_2_NARROW_F64X(F, X, Y) (F ## f128 (X, Y))
# define __TGMATH_3_NARROW_F64X(F, X, Y, Z) (F ## f128 (X, Y, Z))
# if !__HAVE_FLOAT128
# define __TGMATH_1_NARROW_F32X(F, X) (F ## f64 (X))
# define __TGMATH_2_NARROW_F32X(F, X, Y) (F ## f64 (X, Y))
# define __TGMATH_3_NARROW_F32X(F, X, Y, Z) (F ## f64 (X, Y, Z))
# endif
# if __HAVE_BUILTIN_TGMATH
# if __HAVE_FLOAT16 && defined __RLIBC_MATH_FLOATN
# define __TG_F16_ARG(X) X ## f16,
# else
# define __TG_F16_ARG(X)
# endif
# if __HAVE_FLOAT32 && defined __RLIBC_MATH_FLOATN
# define __TG_F32_ARG(X) X ## f32,
# else
# define __TG_F32_ARG(X)
# endif
# if __HAVE_FLOAT64 && defined __RLIBC_MATH_FLOATN
# define __TG_F64_ARG(X) X ## f64,
# else
# define __TG_F64_ARG(X)
# endif
# if __HAVE_FLOAT128 && defined __RLIBC_MATH_FLOATN
# define __TG_F128_ARG(X) X ## f128,
# else
# define __TG_F128_ARG(X)
# endif
# if __HAVE_FLOAT32X && defined __RLIBC_MATH_FLOATN
# define __TG_F32X_ARG(X) X ## f32x,
# else
# define __TG_F32X_ARG(X)
# endif
# if __HAVE_FLOAT64X && defined __RLIBC_MATH_FLOATN
# define __TG_F64X_ARG(X) X ## f64x,
# else
# define __TG_F64X_ARG(X)
# endif
# if __HAVE_FLOAT128X && defined __RLIBC_MATH_FLOATN
# define __TG_F128X_ARG(X) X ## f128x,
# else
# define __TG_F128X_ARG(X)
# endif
# define __TGMATH_FUNCS(X) X ## f, X, X ## l, __TG_F16_ARG (X) __TG_F32_ARG (X) __TG_F64_ARG (X) __TG_F128_ARG (X) __TG_F32X_ARG (X) __TG_F64X_ARG (X) __TG_F128X_ARG (X)
# define __TGMATH_RCFUNCS(F, C) __TGMATH_FUNCS (F) __TGMATH_FUNCS (C)
# define __TGMATH_1(F, X) __builtin_tgmath (__TGMATH_FUNCS (F) (X))
# define __TGMATH_2(F, X, Y) __builtin_tgmath (__TGMATH_FUNCS (F) (X), (Y))
# define __TGMATH_2STD(F, X, Y) __builtin_tgmath (F ## f, F, F ## l, (X), (Y))
# define __TGMATH_3(F, X, Y, Z) __builtin_tgmath (__TGMATH_FUNCS (F) (X), (Y), (Z))
# define __TGMATH_1C(F, C, X) __builtin_tgmath (__TGMATH_RCFUNCS (F, C) (X))
# define __TGMATH_2C(F, C, X, Y) __builtin_tgmath (__TGMATH_RCFUNCS (F, C) (X), (Y))
# define __TGMATH_NARROW_FUNCS_F(X) X, X ## l,
# define __TGMATH_NARROW_FUNCS_F16(X) __TG_F32_ARG (X) __TG_F64_ARG (X) __TG_F128_ARG (X) __TG_F32X_ARG (X) __TG_F64X_ARG (X) __TG_F128X_ARG (X)
# define __TGMATH_NARROW_FUNCS_F32(X) __TG_F64_ARG (X) __TG_F128_ARG (X) __TG_F32X_ARG (X) __TG_F64X_ARG (X) __TG_F128X_ARG (X)
# define __TGMATH_NARROW_FUNCS_F64(X) __TG_F128_ARG (X) __TG_F64X_ARG (X) __TG_F128X_ARG (X)
# define __TGMATH_NARROW_FUNCS_F32X(X) __TG_F64X_ARG (X) __TG_F128X_ARG (X) __TG_F64_ARG (X) __TG_F128_ARG (X)
# define __TGMATH_1_NARROW_F(F, X) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F (F) (X))
# define __TGMATH_2_NARROW_F(F, X, Y) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F (F) (X), (Y))
# define __TGMATH_3_NARROW_F(F, X, Y, Z) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F (F) (X), (Y), (Z))
# define __TGMATH_1_NARROW_F16(F, X) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F16 (F) (X))
# define __TGMATH_2_NARROW_F16(F, X, Y) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F16 (F) (X), (Y))
# define __TGMATH_3_NARROW_F16(F, X, Y, Z) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F16 (F) (X), (Y), (Z))
# define __TGMATH_1_NARROW_F32(F, X) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F32 (F) (X))
# define __TGMATH_2_NARROW_F32(F, X, Y) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F32 (F) (X), (Y))
# define __TGMATH_3_NARROW_F32(F, X, Y, Z) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F32 (F) (X), (Y), (Z))
# define __TGMATH_1_NARROW_F64(F, X) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F64 (F) (X))
# define __TGMATH_2_NARROW_F64(F, X, Y) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F64 (F) (X), (Y))
# define __TGMATH_3_NARROW_F64(F, X, Y, Z) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F64 (F) (X), (Y), (Z))
# if __HAVE_FLOAT128 && __HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_1_NARROW_F32X(F, X) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F32X (F) (X))
# define __TGMATH_2_NARROW_F32X(F, X, Y) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F32X (F) (X), (Y))
# define __TGMATH_3_NARROW_F32X(F, X, Y, Z) __builtin_tgmath (__TGMATH_NARROW_FUNCS_F32X (F) (X), (Y), (Z))
# endif
# endif
# if !__HAVE_BUILTIN_TGMATH_C23
# ifdef __NO_LONG_DOUBLE_MATH
# define __tgml(fct) fct
# else
# define __tgml(fct) fct ## l
# endif
# if __GNUC_PREREQ (3, 1)
# define __floating_type(type) (__builtin_classify_type (__real__ ((type) 0)) == 8)
# define __real_integer_type(type) (__builtin_classify_type ((type) 0) == 1)
# define __complex_integer_type(type) (__builtin_classify_type ((type) 0) == 9 && __builtin_classify_type (__real__ ((type) 0)) == 1)
# else
# define __floating_type(type) (((type) 1.25) != 1)
# define __real_integer_type(type) (((type) (1.25 + _Complex_I)) == 1)
# define __complex_integer_type(type) (((type) (1.25 + _Complex_I)) == (1 + _Complex_I))
# endif
# define __expr_is_real(E) (__builtin_classify_type (E) != 9)
# define __tgmath_type_if(T1, T2, E) __typeof__ (*(0 ? (__typeof__ (0 ? (T2 *) 0 : (void *) (E))) 0 : (__typeof__ (0 ? (T1 *) 0 : (void *) (!(E)))) 0))
# define __tgmath_real_type_sub(T, E) __tgmath_type_if (T, double, E)
# define __tgmath_real_type(expr) __tgmath_real_type_sub (__typeof__ ((__typeof__ (+(expr))) 0), __floating_type (__typeof__ (+(expr))))
# define __tgmath_complex_type_sub(T, E1, E2, E3) __typeof__ (*(0 ? (__typeof__ (0 ? (T *) 0 : (void *) (!(E1)))) 0 : (__typeof__ (0 ? (__typeof__ (0 ? (double *) 0 : (void *) (!(E2)))) 0 : (__typeof__ (0 ? (_Complex double *) 0 : (void *) (!(E3)))) 0)) 0))
# define __tgmath_complex_type(expr) __tgmath_complex_type_sub (__typeof__ ((__typeof__ (+(expr))) 0), __floating_type (__typeof__ (+(expr))), __real_integer_type (__typeof__ (+(expr))), __complex_integer_type (__typeof__ (+(expr))))
# define __tgmath_real_type2_base(expr1, expr2) __typeof ((__tgmath_real_type (expr1)) 0 + (__tgmath_real_type (expr2)) 0)
# define __tgmath_complex_type2_base(expr1, expr2) __typeof ((__tgmath_complex_type (expr1)) 0 + (__tgmath_complex_type (expr2)) 0)
# define __tgmath_real_type3_base(expr1, expr2, expr3) __typeof ((__tgmath_real_type (expr1)) 0 + (__tgmath_real_type (expr2)) 0 + (__tgmath_real_type (expr3)) 0)
# if __HAVE_FLOATN_NOT_TYPEDEF
# define __tgmath_real_type2(expr1, expr2) __tgmath_type_if (_Float32x, __tgmath_real_type2_base (expr1, expr2), _Generic ((expr1) + (expr2), _Float32x: 1, default: 0))
# define __tgmath_complex_type2(expr1, expr2) __tgmath_type_if (_Float32x, __tgmath_type_if (_Complex _Float32x, __tgmath_complex_type2_base (expr1, expr2), _Generic ((expr1) + (expr2), _Complex _Float32x: 1, default: 0)), _Generic ((expr1) + (expr2), _Float32x: 1, default: 0))
# define __tgmath_real_type3(expr1, expr2, expr3) __tgmath_type_if (_Float32x, __tgmath_real_type3_base (expr1, expr2, expr3), _Generic ((expr1) + (expr2) + (expr3), _Float32x: 1, default: 0))
# else
# define __tgmath_real_type2(expr1, expr2) __tgmath_real_type2_base (expr1, expr2)
# define __tgmath_complex_type2(expr1, expr2) __tgmath_complex_type2_base (expr1, expr2)
# define __tgmath_real_type3(expr1, expr2, expr3) __tgmath_real_type3_base (expr1, expr2, expr3)
# endif
# if (__HAVE_DISTINCT_FLOAT16 || __HAVE_DISTINCT_FLOAT32 || __HAVE_DISTINCT_FLOAT64 || __HAVE_DISTINCT_FLOAT32X || __HAVE_DISTINCT_FLOAT64X || __HAVE_DISTINCT_FLOAT128X)
# error "Unsupported _FloatN or _FloatNx types for <tgmath.h>."
# endif
# if __HAVE_DISTINCT_FLOAT128 && defined __RLIBC_MATH_FLOATN
# if (!__HAVE_FLOAT64X || __HAVE_FLOAT64X_LONG_DOUBLE || !__HAVE_FLOATN_NOT_TYPEDEF)
# define __TGMATH_F128(arg_comb, fct, arg_call) __builtin_types_compatible_p (__typeof (+(arg_comb)), _Float128) ? fct ## f128 arg_call :
# define __TGMATH_F128LD(arg_comb, fct, arg_call) (__builtin_types_compatible_p (__typeof (+(arg_comb)), _Float128) || __builtin_types_compatible_p (__typeof (+(arg_comb)), long double)) ? fct ## f128 arg_call :
# define __TGMATH_CF128(arg_comb, fct, cfct, arg_call) __builtin_types_compatible_p (__typeof (+__real__ (arg_comb)), _Float128) ? (__expr_is_real (arg_comb) ? fct ## f128 arg_call : cfct ## f128 arg_call) :
# else
# define __TGMATH_F128(arg_comb, fct, arg_call) (__builtin_types_compatible_p (__typeof (+(arg_comb)), _Float128) || __builtin_types_compatible_p (__typeof (+(arg_comb)), _Float64x)) ? fct ## f128 arg_call :
# define __TGMATH_CF128(arg_comb, fct, cfct, arg_call) (__builtin_types_compatible_p (__typeof (+__real__ (arg_comb)), _Float128) || __builtin_types_compatible_p (__typeof (+__real__ (arg_comb)), _Float64x)) ? (__expr_is_real (arg_comb) ? fct ## f128 arg_call : cfct ## f128 arg_call) :
# endif
# else
# define __TGMATH_F128(arg_comb, fct, arg_call)
# define __TGMATH_CF128(arg_comb, fct, cfct, arg_call)
# endif
# endif
# if __HAVE_BUILTIN_TGMATH
# define __TGMATH_UNARY_REAL_ONLY(Val, Fct) __TGMATH_1 (Fct, (Val))
# define __TGMATH_UNARY_REAL_RET_ONLY(Val, Fct) __TGMATH_1 (Fct, (Val))
# define __TGMATH_BINARY_FIRST_REAL_ONLY(Val1, Val2, Fct) __TGMATH_2 (Fct, (Val1), (Val2))
# define __TGMATH_BINARY_FIRST_REAL_STD_ONLY(Val1, Val2, Fct) __TGMATH_2STD (Fct, (Val1), (Val2))
# if __HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_BINARY_REAL_ONLY(Val1, Val2, Fct) __TGMATH_2 (Fct, (Val1), (Val2))
# endif
# define __TGMATH_BINARY_REAL_STD_ONLY(Val1, Val2, Fct) __TGMATH_2STD (Fct, (Val1), (Val2))
# if __HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_TERNARY_FIRST_SECOND_REAL_ONLY(Val1, Val2, Val3, Fct) __TGMATH_3 (Fct, (Val1), (Val2), (Val3))
# define __TGMATH_TERNARY_REAL_ONLY(Val1, Val2, Val3, Fct) __TGMATH_3 (Fct, (Val1), (Val2), (Val3))
# endif
# define __TGMATH_TERNARY_FIRST_REAL_ONLY(Val1, Val2, Val3, Fct) __TGMATH_3 (Fct, (Val1), (Val2), (Val3))
# define __TGMATH_UNARY_REAL_IMAG(Val, Fct, Cfct) __TGMATH_1C (Fct, Cfct, (Val))
# define __TGMATH_UNARY_IMAG(Val, Cfct) __TGMATH_1 (Cfct, (Val))
# define __TGMATH_UNARY_REAL_IMAG_RET_REAL(Val, Fct, Cfct) __TGMATH_1C (Fct, Cfct, (Val))
# define __TGMATH_UNARY_REAL_IMAG_RET_REAL_SAME(Val, Cfct) __TGMATH_1 (Cfct, (Val))
# if __HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_BINARY_REAL_IMAG(Val1, Val2, Fct, Cfct) __TGMATH_2C (Fct, Cfct, (Val1), (Val2))
# endif
# endif
# if !__HAVE_BUILTIN_TGMATH
# define __TGMATH_UNARY_REAL_ONLY(Val, Fct) (__extension__ ((sizeof (+(Val)) == sizeof (double) || __builtin_classify_type (Val) != 8) ? (__tgmath_real_type (Val)) Fct (Val) : (sizeof (+(Val)) == sizeof (float)) ? (__tgmath_real_type (Val)) Fct##f (Val) : __TGMATH_F128 ((Val), (__tgmath_real_type (Val)) Fct, (Val)) (__tgmath_real_type (Val)) __tgml(Fct) (Val)))
# define __TGMATH_UNARY_REAL_RET_ONLY(Val, Fct) (__extension__ ((sizeof (+(Val)) == sizeof (double) || __builtin_classify_type (Val) != 8) ? Fct (Val) : (sizeof (+(Val)) == sizeof (float)) ? Fct##f (Val) : __TGMATH_F128 ((Val), Fct, (Val)) __tgml(Fct) (Val)))
# define __TGMATH_BINARY_FIRST_REAL_ONLY(Val1, Val2, Fct) (__extension__ ((sizeof (+(Val1)) == sizeof (double) || __builtin_classify_type (Val1) != 8) ? (__tgmath_real_type (Val1)) Fct (Val1, Val2) : (sizeof (+(Val1)) == sizeof (float)) ? (__tgmath_real_type (Val1)) Fct##f (Val1, Val2) : __TGMATH_F128 ((Val1), (__tgmath_real_type (Val1)) Fct, (Val1, Val2)) (__tgmath_real_type (Val1)) __tgml(Fct) (Val1, Val2)))
# define __TGMATH_BINARY_FIRST_REAL_STD_ONLY(Val1, Val2, Fct) (__extension__ ((sizeof (+(Val1)) == sizeof (double) || __builtin_classify_type (Val1) != 8) ? (__tgmath_real_type (Val1)) Fct (Val1, Val2) : (sizeof (+(Val1)) == sizeof (float)) ? (__tgmath_real_type (Val1)) Fct##f (Val1, Val2) : (__tgmath_real_type (Val1)) __tgml(Fct) (Val1, Val2)))
# endif
# if !__HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_BINARY_REAL_ONLY(Val1, Val2, Fct) (__extension__ ((sizeof ((Val1) + (Val2)) > sizeof (double) && __builtin_classify_type ((Val1) + (Val2)) == 8) ? __TGMATH_F128 ((Val1) + (Val2), (__tgmath_real_type2 (Val1, Val2)) Fct, (Val1, Val2)) (__tgmath_real_type2 (Val1, Val2)) __tgml(Fct) (Val1, Val2) : (sizeof (+(Val1)) == sizeof (double) || sizeof (+(Val2)) == sizeof (double) || __builtin_classify_type (Val1) != 8 || __builtin_classify_type (Val2) != 8) ? (__tgmath_real_type2 (Val1, Val2)) Fct (Val1, Val2) : (__tgmath_real_type2 (Val1, Val2)) Fct##f (Val1, Val2)))
# endif
# if !__HAVE_BUILTIN_TGMATH
# define __TGMATH_BINARY_REAL_STD_ONLY(Val1, Val2, Fct) (__extension__ ((sizeof ((Val1) + (Val2)) > sizeof (double) && __builtin_classify_type ((Val1) + (Val2)) == 8) ? (__typeof ((__tgmath_real_type (Val1)) 0 + (__tgmath_real_type (Val2)) 0)) __tgml(Fct) (Val1, Val2) : (sizeof (+(Val1)) == sizeof (double) || sizeof (+(Val2)) == sizeof (double) || __builtin_classify_type (Val1) != 8 || __builtin_classify_type (Val2) != 8) ? (__typeof ((__tgmath_real_type (Val1)) 0 + (__tgmath_real_type (Val2)) 0)) Fct (Val1, Val2) : (__typeof ((__tgmath_real_type (Val1)) 0 + (__tgmath_real_type (Val2)) 0)) Fct##f (Val1, Val2)))
# endif
# if !__HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_TERNARY_FIRST_SECOND_REAL_ONLY(Val1, Val2, Val3, Fct) (__extension__ ((sizeof ((Val1) + (Val2)) > sizeof (double) && __builtin_classify_type ((Val1) + (Val2)) == 8) ? __TGMATH_F128 ((Val1) + (Val2), (__tgmath_real_type2 (Val1, Val2)) Fct, (Val1, Val2, Val3)) (__tgmath_real_type2 (Val1, Val2)) __tgml(Fct) (Val1, Val2, Val3) : (sizeof (+(Val1)) == sizeof (double) || sizeof (+(Val2)) == sizeof (double) || __builtin_classify_type (Val1) != 8 || __builtin_classify_type (Val2) != 8) ? (__tgmath_real_type2 (Val1, Val2)) Fct (Val1, Val2, Val3) : (__tgmath_real_type2 (Val1, Val2)) Fct##f (Val1, Val2, Val3)))
# define __TGMATH_TERNARY_REAL_ONLY(Val1, Val2, Val3, Fct) (__extension__ ((sizeof ((Val1) + (Val2) + (Val3)) > sizeof (double) && __builtin_classify_type ((Val1) + (Val2) + (Val3)) == 8) ? __TGMATH_F128 ((Val1) + (Val2) + (Val3), (__tgmath_real_type3 (Val1, Val2, Val3)) Fct, (Val1, Val2, Val3)) (__tgmath_real_type3 (Val1, Val2, Val3)) __tgml(Fct) (Val1, Val2, Val3) : (sizeof (+(Val1)) == sizeof (double) || sizeof (+(Val2)) == sizeof (double) || sizeof (+(Val3)) == sizeof (double) || __builtin_classify_type (Val1) != 8 || __builtin_classify_type (Val2) != 8 || __builtin_classify_type (Val3) != 8) ? (__tgmath_real_type3 (Val1, Val2, Val3)) Fct (Val1, Val2, Val3) : (__tgmath_real_type3 (Val1, Val2, Val3)) Fct##f (Val1, Val2, Val3)))
# endif
# if !__HAVE_BUILTIN_TGMATH
# define __TGMATH_TERNARY_FIRST_REAL_ONLY(Val1, Val2, Val3, Fct) (__extension__ ((sizeof (+(Val1)) == sizeof (double) || __builtin_classify_type (Val1) != 8) ? (__tgmath_real_type (Val1)) Fct (Val1, Val2, Val3) : (sizeof (+(Val1)) == sizeof (float)) ? (__tgmath_real_type (Val1)) Fct##f (Val1, Val2, Val3) : __TGMATH_F128 ((Val1), (__tgmath_real_type (Val1)) Fct, (Val1, Val2, Val3)) (__tgmath_real_type (Val1)) __tgml(Fct) (Val1, Val2, Val3)))
# define __TGMATH_UNARY_REAL_IMAG(Val, Fct, Cfct) (__extension__ ((sizeof (+__real__ (Val)) == sizeof (double) || __builtin_classify_type (__real__ (Val)) != 8) ? (__expr_is_real (Val) ? (__tgmath_complex_type (Val)) Fct (Val) : (__tgmath_complex_type (Val)) Cfct (Val)) : (sizeof (+__real__ (Val)) == sizeof (float)) ? (__expr_is_real (Val) ? (__tgmath_complex_type (Val)) Fct##f (Val) : (__tgmath_complex_type (Val)) Cfct##f (Val)) : __TGMATH_CF128 ((Val), (__tgmath_complex_type (Val)) Fct, (__tgmath_complex_type (Val)) Cfct, (Val)) (__expr_is_real (Val) ? (__tgmath_complex_type (Val)) __tgml(Fct) (Val) : (__tgmath_complex_type (Val)) __tgml(Cfct) (Val))))
# define __TGMATH_UNARY_IMAG(Val, Cfct) (__extension__ ((sizeof (+__real__ (Val)) == sizeof (double) || __builtin_classify_type (__real__ (Val)) != 8) ? (__typeof__ ((__tgmath_real_type (Val)) 0 + _Complex_I)) Cfct (Val) : (sizeof (+__real__ (Val)) == sizeof (float)) ? (__typeof__ ((__tgmath_real_type (Val)) 0 + _Complex_I)) Cfct##f (Val) : __TGMATH_F128 (__real__ (Val), (__typeof__ ((__tgmath_real_type (Val)) 0 + _Complex_I)) Cfct, (Val)) (__typeof__ ((__tgmath_real_type (Val)) 0 + _Complex_I)) __tgml(Cfct) (Val)))
# define __TGMATH_UNARY_REAL_IMAG_RET_REAL(Val, Fct, Cfct) (__extension__ ((sizeof (+__real__ (Val)) == sizeof (double) || __builtin_classify_type (__real__ (Val)) != 8) ? (__expr_is_real (Val) ? (__typeof__ (__real__ (__tgmath_real_type (Val)) 0)) Fct (Val) : (__typeof__ (__real__ (__tgmath_real_type (Val)) 0)) Cfct (Val)) : (sizeof (+__real__ (Val)) == sizeof (float)) ? (__expr_is_real (Val) ? (__typeof__ (__real__ (__tgmath_real_type (Val)) 0)) Fct##f (Val) : (__typeof__ (__real__ (__tgmath_real_type (Val)) 0)) Cfct##f (Val)) : __TGMATH_CF128 ((Val), (__typeof__ (__real__ (__tgmath_real_type (Val)) 0)) Fct, (__typeof__ (__real__ (__tgmath_real_type (Val)) 0)) Cfct, (Val)) (__expr_is_real (Val) ? (__typeof__ (__real__ (__tgmath_real_type (Val)) 0)) __tgml(Fct) (Val) : (__typeof__ (__real__ (__tgmath_real_type (Val)) 0)) __tgml(Cfct) (Val))))
# define __TGMATH_UNARY_REAL_IMAG_RET_REAL_SAME(Val, Cfct) __TGMATH_UNARY_REAL_IMAG_RET_REAL ((Val), Cfct, Cfct)
# endif
# if !__HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_BINARY_REAL_IMAG(Val1, Val2, Fct, Cfct) (__extension__ ((sizeof (__real__ (Val1) + __real__ (Val2)) > sizeof (double) && __builtin_classify_type (__real__ (Val1) + __real__ (Val2)) == 8) ? __TGMATH_CF128 ((Val1) + (Val2), (__tgmath_complex_type2 (Val1, Val2)) Fct, (__tgmath_complex_type2 (Val1, Val2)) Cfct, (Val1, Val2)) (__expr_is_real ((Val1) + (Val2)) ? (__tgmath_complex_type2 (Val1, Val2)) __tgml(Fct) (Val1, Val2) : (__tgmath_complex_type2 (Val1, Val2)) __tgml(Cfct) (Val1, Val2)) : (sizeof (+__real__ (Val1)) == sizeof (double) || sizeof (+__real__ (Val2)) == sizeof (double) || __builtin_classify_type (__real__ (Val1)) != 8 || __builtin_classify_type (__real__ (Val2)) != 8) ? (__expr_is_real ((Val1) + (Val2)) ? (__tgmath_complex_type2 (Val1, Val2)) Fct (Val1, Val2) : (__tgmath_complex_type2 (Val1, Val2)) Cfct (Val1, Val2)) : (__expr_is_real ((Val1) + (Val2)) ? (__tgmath_complex_type2 (Val1, Val2)) Fct##f (Val1, Val2) : (__tgmath_complex_type2 (Val1, Val2)) Cfct##f (Val1, Val2))))
# endif
# if !__HAVE_BUILTIN_TGMATH
# define __TGMATH_1_NARROW_F(F, X) (__extension__ (sizeof ((__tgmath_real_type (X)) 0) > sizeof (double) ? F ## l (X) : F (X)))
# define __TGMATH_2_NARROW_F(F, X, Y) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0) > sizeof (double) ? F ## l (X, Y) : F (X, Y)))
# define __TGMATH_3_NARROW_F(F, X, Y, Z) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0 + (__tgmath_real_type (Z)) 0) > sizeof (double) ? F ## l (X, Y, Z) : F (X, Y, Z)))
# endif
# if !__HAVE_BUILTIN_TGMATH_C23
# if __HAVE_FLOATN_NOT_TYPEDEF
# define __TGMATH_NARROW_F32X_USE_F64X(X) !__builtin_types_compatible_p (__typeof (+(X)), _Float64)
# else
# define __TGMATH_NARROW_F32X_USE_F64X(X) (__builtin_types_compatible_p (__typeof (+(X)), double) || __builtin_types_compatible_p (__typeof (+(X)), float) || !__floating_type (__typeof (+(X))))
# endif
# endif
# if __HAVE_FLOAT64X_LONG_DOUBLE && __HAVE_DISTINCT_FLOAT128
# if !__HAVE_BUILTIN_TGMATH
# define __TGMATH_1_NARROW_F32(F, X) (__extension__ (sizeof ((__tgmath_real_type (X)) 0) > sizeof (_Float64) ? __TGMATH_F128LD ((X), F, (X)) F ## f64x (X) : F ## f64 (X)))
# define __TGMATH_2_NARROW_F32(F, X, Y) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0) > sizeof (_Float64) ? __TGMATH_F128LD ((X) + (Y), F, (X, Y)) F ## f64x (X, Y) : F ## f64 (X, Y)))
# define __TGMATH_3_NARROW_F32(F, X, Y, Z) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0 + (__tgmath_real_type (Z)) 0) > sizeof (_Float64) ? __TGMATH_F128LD ((X) + (Y) + (Z), F, (X, Y, Z)) F ## f64x (X, Y, Z) : F ## f64 (X, Y, Z)))
# define __TGMATH_1_NARROW_F64(F, X) (__extension__ (sizeof ((__tgmath_real_type (X)) 0) > sizeof (_Float64) ? __TGMATH_F128LD ((X), F, (X)) F ## f64x (X) : F ## f128 (X)))
# define __TGMATH_2_NARROW_F64(F, X, Y) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0) > sizeof (_Float64) ? __TGMATH_F128LD ((X) + (Y), F, (X, Y)) F ## f64x (X, Y) : F ## f128 (X, Y)))
# define __TGMATH_3_NARROW_F64(F, X, Y, Z) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0 + (__tgmath_real_type (Z)) 0) > sizeof (_Float64) ? __TGMATH_F128LD ((X) + (Y) + (Z), F, (X, Y, Z)) F ## f64x (X, Y, Z) : F ## f128 (X, Y, Z)))
# endif
# if !__HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_1_NARROW_F32X(F, X) (__extension__ (sizeof ((__tgmath_real_type (X)) 0) > sizeof (_Float64) || __TGMATH_NARROW_F32X_USE_F64X (X) ? __TGMATH_F128 ((X), F, (X)) F ## f64x (X) : F ## f64 (X)))
# define __TGMATH_2_NARROW_F32X(F, X, Y) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0) > sizeof (_Float64) || __TGMATH_NARROW_F32X_USE_F64X ((X) + (Y)) ? __TGMATH_F128 ((X) + (Y), F, (X, Y)) F ## f64x (X, Y) : F ## f64 (X, Y)))
# define __TGMATH_3_NARROW_F32X(F, X, Y, Z) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0 + (__tgmath_real_type (Z)) 0) > sizeof (_Float64) || __TGMATH_NARROW_F32X_USE_F64X ((X) + (Y) + (Z)) ? __TGMATH_F128 ((X) + (Y) + (Z), F, (X, Y, Z)) F ## f64x (X, Y, Z) : F ## f64 (X, Y, Z)))
# endif
# elif __HAVE_FLOAT128
# if !__HAVE_BUILTIN_TGMATH
# define __TGMATH_1_NARROW_F32(F, X) (__extension__ (sizeof ((__tgmath_real_type (X)) 0) > sizeof (_Float64) ? F ## f128 (X) : F ## f64 (X)))
# define __TGMATH_2_NARROW_F32(F, X, Y) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0) > sizeof (_Float64) ? F ## f128 (X, Y) : F ## f64 (X, Y)))
# define __TGMATH_3_NARROW_F32(F, X, Y, Z) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0 + (__tgmath_real_type (Z)) 0) > sizeof (_Float64) ? F ## f128 (X, Y, Z) : F ## f64 (X, Y, Z)))
# define __TGMATH_1_NARROW_F64(F, X) (F ## f128 (X))
# define __TGMATH_2_NARROW_F64(F, X, Y) (F ## f128 (X, Y))
# define __TGMATH_3_NARROW_F64(F, X, Y, Z) (F ## f128 (X, Y, Z))
# endif
# if !__HAVE_BUILTIN_TGMATH_C23
# define __TGMATH_1_NARROW_F32X(F, X) (__extension__ (sizeof ((__tgmath_real_type (X)) 0) > sizeof (_Float32x) || __TGMATH_NARROW_F32X_USE_F64X (X) ? F ## f64x (X) : F ## f64 (X)))
# define __TGMATH_2_NARROW_F32X(F, X, Y) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0) > sizeof (_Float32x) || __TGMATH_NARROW_F32X_USE_F64X ((X) + (Y)) ? F ## f64x (X, Y) : F ## f64 (X, Y)))
# define __TGMATH_3_NARROW_F32X(F, X, Y, Z) (__extension__ (sizeof ((__tgmath_real_type (X)) 0 + (__tgmath_real_type (Y)) 0 + (__tgmath_real_type (Z)) 0) > sizeof (_Float32x) || __TGMATH_NARROW_F32X_USE_F64X ((X) + (Y) + (Z)) ? F ## f64x (X, Y, Z) : F ## f64 (X, Y, Z)))
# endif
# else
# if !__HAVE_BUILTIN_TGMATH
# define __TGMATH_1_NARROW_F32(F, X) (F ## f64 (X))
# define __TGMATH_2_NARROW_F32(F, X, Y) (F ## f64 (X, Y))
# define __TGMATH_3_NARROW_F32(F, X, Y, Z) (F ## f64 (X, Y, Z))
# endif
# endif
#else
# error "Unsupported compiler; you cannot use <tgmath.h>"
#endif"#),
            Item::Blank,
            Item::Raw(Reason::StdMacro, r#"#define acos(Val) __TGMATH_UNARY_REAL_IMAG (Val, acos, cacos)
#define asin(Val) __TGMATH_UNARY_REAL_IMAG (Val, asin, casin)
#define atan(Val) __TGMATH_UNARY_REAL_IMAG (Val, atan, catan)
#define atan2(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, atan2)
#define cos(Val) __TGMATH_UNARY_REAL_IMAG (Val, cos, ccos)
#define sin(Val) __TGMATH_UNARY_REAL_IMAG (Val, sin, csin)
#define tan(Val) __TGMATH_UNARY_REAL_IMAG (Val, tan, ctan)
#if defined __RLIBC_MATH_EXT
# define acospi(Val) __TGMATH_UNARY_REAL_ONLY (Val, acospi)
# define asinpi(Val) __TGMATH_UNARY_REAL_ONLY (Val, asinpi)
# define atanpi(Val) __TGMATH_UNARY_REAL_ONLY (Val, atanpi)
#define atan2pi(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, atan2pi)
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
#if defined __RLIBC_MATH_EXT
#define exp10(Val) __TGMATH_UNARY_REAL_ONLY (Val, exp10)
#define exp2m1(Val) __TGMATH_UNARY_REAL_ONLY (Val, exp2m1)
#define exp10m1(Val) __TGMATH_UNARY_REAL_ONLY (Val, exp10m1)
#define log2p1(Val) __TGMATH_UNARY_REAL_ONLY (Val, log2p1)
#define log10p1(Val) __TGMATH_UNARY_REAL_ONLY (Val, log10p1)
#define logp1(Val) __TGMATH_UNARY_REAL_ONLY (Val, logp1)
#endif
#define pow(Val1, Val2) __TGMATH_BINARY_REAL_IMAG (Val1, Val2, pow, cpow)
#define sqrt(Val) __TGMATH_UNARY_REAL_IMAG (Val, sqrt, csqrt)
#define hypot(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, hypot)
#define cbrt(Val) __TGMATH_UNARY_REAL_ONLY (Val, cbrt)
#if defined __RLIBC_MATH_EXT
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
#if defined __RLIBC_MATH_EXT
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
#if __GLIBC_USE (ISOC23) && !defined __USE_GNU
# define fmax(Val1, Val2) __TGMATH_BINARY_REAL_STD_ONLY (Val1, Val2, fmax)
# define fmin(Val1, Val2) __TGMATH_BINARY_REAL_STD_ONLY (Val1, Val2, fmin)
#else
# define fmax(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmax)
# define fmin(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmin)
#endif
#define fma(Val1, Val2, Val3) __TGMATH_TERNARY_REAL_ONLY (Val1, Val2, Val3, fma)
#if defined __RLIBC_MATH_EXT
# define roundeven(Val) __TGMATH_UNARY_REAL_ONLY (Val, roundeven)
# define fromfp(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_REAL_ONLY (Val1, Val2, Val3, fromfp)
# define ufromfp(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_REAL_ONLY (Val1, Val2, Val3, ufromfp)
# define fromfpx(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_REAL_ONLY (Val1, Val2, Val3, fromfpx)
# define ufromfpx(Val1, Val2, Val3) __TGMATH_TERNARY_FIRST_REAL_ONLY (Val1, Val2, Val3, ufromfpx)
# define llogb(Val) __TGMATH_UNARY_REAL_RET_ONLY (Val, llogb)
#endif
#if defined __RLIBC_MATH_EXT
# define fmaxmag(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fmaxmag)
# define fminmag(Val1, Val2) __TGMATH_BINARY_REAL_ONLY (Val1, Val2, fminmag)
#endif
#if __GLIBC_USE (ISOC23)
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
#if defined __RLIBC_MATH_EXT
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
#if defined __RLIBC_MATH_FLOATN
# if __HAVE_FLOAT16
# define f16add(Val1, Val2) __TGMATH_2_NARROW_F16 (f16add, Val1, Val2)
# define f16div(Val1, Val2) __TGMATH_2_NARROW_F16 (f16div, Val1, Val2)
# define f16mul(Val1, Val2) __TGMATH_2_NARROW_F16 (f16mul, Val1, Val2)
# define f16sub(Val1, Val2) __TGMATH_2_NARROW_F16 (f16sub, Val1, Val2)
# define f16sqrt(Val) __TGMATH_1_NARROW_F16 (f16sqrt, Val)
# define f16fma(Val1, Val2, Val3) __TGMATH_3_NARROW_F16 (f16fma, Val1, Val2, Val3)
# endif
# if __HAVE_FLOAT32
# define f32add(Val1, Val2) __TGMATH_2_NARROW_F32 (f32add, Val1, Val2)
# define f32div(Val1, Val2) __TGMATH_2_NARROW_F32 (f32div, Val1, Val2)
# define f32mul(Val1, Val2) __TGMATH_2_NARROW_F32 (f32mul, Val1, Val2)
# define f32sub(Val1, Val2) __TGMATH_2_NARROW_F32 (f32sub, Val1, Val2)
# define f32sqrt(Val) __TGMATH_1_NARROW_F32 (f32sqrt, Val)
# define f32fma(Val1, Val2, Val3) __TGMATH_3_NARROW_F32 (f32fma, Val1, Val2, Val3)
# endif
# if __HAVE_FLOAT64 && (__HAVE_FLOAT64X || __HAVE_FLOAT128)
# define f64add(Val1, Val2) __TGMATH_2_NARROW_F64 (f64add, Val1, Val2)
# define f64div(Val1, Val2) __TGMATH_2_NARROW_F64 (f64div, Val1, Val2)
# define f64mul(Val1, Val2) __TGMATH_2_NARROW_F64 (f64mul, Val1, Val2)
# define f64sub(Val1, Val2) __TGMATH_2_NARROW_F64 (f64sub, Val1, Val2)
# define f64sqrt(Val) __TGMATH_1_NARROW_F64 (f64sqrt, Val)
# define f64fma(Val1, Val2, Val3) __TGMATH_3_NARROW_F64 (f64fma, Val1, Val2, Val3)
# endif
# if __HAVE_FLOAT32X
# define f32xadd(Val1, Val2) __TGMATH_2_NARROW_F32X (f32xadd, Val1, Val2)
# define f32xdiv(Val1, Val2) __TGMATH_2_NARROW_F32X (f32xdiv, Val1, Val2)
# define f32xmul(Val1, Val2) __TGMATH_2_NARROW_F32X (f32xmul, Val1, Val2)
# define f32xsub(Val1, Val2) __TGMATH_2_NARROW_F32X (f32xsub, Val1, Val2)
# define f32xsqrt(Val) __TGMATH_1_NARROW_F32X (f32xsqrt, Val)
# define f32xfma(Val1, Val2, Val3) __TGMATH_3_NARROW_F32X (f32xfma, Val1, Val2, Val3)
# endif
# if __HAVE_FLOAT64X && (__HAVE_FLOAT128X || __HAVE_FLOAT128)
# define f64xadd(Val1, Val2) __TGMATH_2_NARROW_F64X (f64xadd, Val1, Val2)
# define f64xdiv(Val1, Val2) __TGMATH_2_NARROW_F64X (f64xdiv, Val1, Val2)
# define f64xmul(Val1, Val2) __TGMATH_2_NARROW_F64X (f64xmul, Val1, Val2)
# define f64xsub(Val1, Val2) __TGMATH_2_NARROW_F64X (f64xsub, Val1, Val2)
# define f64xsqrt(Val) __TGMATH_1_NARROW_F64X (f64xsqrt, Val)
# define f64xfma(Val1, Val2, Val3) __TGMATH_3_NARROW_F64X (f64xfma, Val1, Val2, Val3)
# endif
#endif"#),
            Item::Blank,
        ]},
    ],
};
