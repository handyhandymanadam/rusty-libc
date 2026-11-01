use crate::model::*;

pub static HDR: Header = Header {
    path: "math.h",
    items: &[
        Item::Comment(r#"/* math.h for the Rust libc. Written by hand: feature macros, constants and the type-generic macros
   (glibc's layout and values). The function declarations come from two generated files,
   bits/rlibc-mathcalls.h (cbindgen, from crates/rusty-libc-math) and bits/rlibc-mathaliases.h
   (tools/math_headers.py, for the functions the Rust sources make with macros).
   The long double (l) functions and the _Float64x names come from bits/rlibc-mathldcalls.h
   (tools/math_headers.py, longdouble_header); the _Float128 names and the narrowing operations come from
   bits/rlibc-mathquadcalls.h (quad_header). Not provided: the _Float16 names. */"#),
        Item::Guard { name: "_RLIBC_MATH_H", value: "1", end: " /* math.h */", items: &[
            Item::Blank,
            Item::Comment(r#"/* Feature tiers, in the way glibc's features.h would set them (simplified: the tiers are tested
   from the standard macros only).
     __RLIBC_MATH_MISC    BSD/SysV extras (isinf, finite, drem, scalb, M_PI, ...): default mode,
                          off in strict ISO mode unless _DEFAULT_SOURCE/_GNU_SOURCE/_XOPEN_SOURCE
     __RLIBC_MATH_GNU     _GNU_SOURCE (sincos, M_PIl, ...)
     __RLIBC_MATH_EXT     C23 and IEC 60559 extension functions (exp10, sinpi, fromfp, nextup,
                          fmaximum, totalorder, ...): _GNU_SOURCE, __STDC_WANT_IEC_60559_*_EXT__,
                          or C23 mode
     __RLIBC_MATH_FLOATN  _Float32/_Float64/_Float32x names: _GNU_SOURCE or
                          __STDC_WANT_IEC_60559_TYPES_EXT__ */"#),
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined _DEFAULT_SOURCE || defined _BSD_SOURCE || defined _SVID_SOURCE \
    || defined _XOPEN_SOURCE || !defined __STRICT_ANSI__"#, items: &[
                    Item::Gate(&[
                        Branch { head: "ifndef __RLIBC_MATH_MISC", items: &[
                            Item::Consts(&[
                                ("__RLIBC_MATH_MISC", V::Dec(1)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef _GNU_SOURCE", items: &[
                    Item::Gate(&[
                        Branch { head: "ifndef __RLIBC_MATH_GNU", items: &[
                            Item::Consts(&[
                                ("__RLIBC_MATH_GNU", V::Dec(1)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: r#"if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_BFP_EXT__ || defined __STDC_WANT_IEC_60559_FUNCS_EXT__ \
    || defined __STDC_WANT_IEC_60559_EXT__ || (defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L)"#, items: &[
                    Item::Gate(&[
                        Branch { head: "ifndef __RLIBC_MATH_EXT", items: &[
                            Item::Consts(&[
                                ("__RLIBC_MATH_EXT", V::Dec(1)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_TYPES_EXT__", items: &[
                    Item::Gate(&[
                        Branch { head: "ifndef __RLIBC_MATH_FLOATN", items: &[
                            Item::Consts(&[
                                ("__RLIBC_MATH_FLOATN", V::Dec(1)),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment("/* The functions come first (isnan, isinf and finite are functions as well as macros). */"),
            Item::Include("<bits/rlibc-mathcalls.h>"),
            Item::Include("<bits/rlibc-mathaliases.h>"),
            Item::Include("<bits/rlibc-mathldcalls.h>"),
            Item::Include("<bits/rlibc-mathquadcalls.h>"),
            Item::Blank,
            Item::Comment("/* HUGE_VAL, INFINITY, NAN */"),
            Item::Consts(&[
                ("HUGE_VAL", V::Txt("(__builtin_huge_val ())")),
                ("HUGE_VALF", V::Txt("(__builtin_huge_valf ())")),
                ("HUGE_VALL", V::Txt("(__builtin_huge_vall ())")),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MATH_FLOATN", items: &[
                    Item::Consts(&[
                        ("HUGE_VAL_F32", V::Txt("(__builtin_huge_valf32 ())")),
                        ("HUGE_VAL_F64", V::Txt("(__builtin_huge_valf64 ())")),
                        ("HUGE_VAL_F32X", V::Txt("(__builtin_huge_valf32x ())")),
                        ("HUGE_VAL_F64X", V::Txt("(__builtin_huge_valf64x ())")),
                        ("HUGE_VAL_F128", V::Txt("(__builtin_huge_valf128 ())")),
                        ("SNANF128", V::Txt(r#"(__builtin_nansf128 (""))"#)),
                    ]),
                ] },
            ], ""),
            Item::Consts(&[
                ("INFINITY", V::Txt("(__builtin_inff ())")),
                ("NAN", V::Txt(r#"(__builtin_nanf (""))"#)),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MATH_EXT", items: &[
                    Item::Consts(&[
                        ("SNANF", V::Txt(r#"(__builtin_nansf (""))"#)),
                        ("SNAN", V::Txt(r#"(__builtin_nans (""))"#)),
                        ("SNANL", V::Txt(r#"(__builtin_nansl (""))"#)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __RLIBC_MATH_GNU && defined __RLIBC_MATH_FLOATN", items: &[
                    Item::Consts(&[
                        ("SNANF32", V::Txt(r#"(__builtin_nansf32 (""))"#)),
                        ("SNANF64", V::Txt(r#"(__builtin_nansf64 (""))"#)),
                        ("SNANF32X", V::Txt(r#"(__builtin_nansf32x (""))"#)),
                        ("SNANF64X", V::Txt(r#"(__builtin_nansf64x (""))"#)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment("/* Evaluation types: FLT_EVAL_METHOD is 0 with SSE on x86-64, 2 with -mfpmath=387 (glibc's bits/mathdef.h) */"),
            Item::Gate(&[
                Branch { head: "if defined __FLT_EVAL_METHOD__ && __FLT_EVAL_METHOD__ == 2", items: &[
                    Item::Typedef("long double", "float_t"),
                    Item::Typedef("long double", "double_t"),
                ] },
                Branch { head: "elif defined __FLT_EVAL_METHOD__ && __FLT_EVAL_METHOD__ == 1", items: &[
                    Item::Typedef("double", "float_t"),
                    Item::Typedef("double", "double_t"),
                ] },
                Branch { head: "else", items: &[
                    Item::Typedef("float", "float_t"),
                    Item::Typedef("double", "double_t"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __RLIBC_MATH_FLOATN || defined __RLIBC_MATH_EXT", items: &[
                    Item::Typedef("long double", "long_double_t"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MATH_FLOATN", items: &[
                    Item::Gate(&[
                        Branch { head: "if defined __FLT_EVAL_METHOD__ && __FLT_EVAL_METHOD__ == 2", items: &[
                            Item::Typedef("long double", "_Float32_t"),
                            Item::Typedef("long double", "_Float64_t"),
                            Item::Typedef("long double", "_Float32x_t"),
                            Item::Typedef("long double", "_Float64x_t"),
                        ] },
                        Branch { head: "elif defined __FLT_EVAL_METHOD__ && __FLT_EVAL_METHOD__ == 1", items: &[
                            Item::Typedef("double", "_Float32_t"),
                            Item::Typedef("_Float64", "_Float64_t"),
                            Item::Typedef("double", "_Float32x_t"),
                            Item::Typedef("_Float64x", "_Float64x_t"),
                        ] },
                        Branch { head: "else", items: &[
                            Item::Typedef("_Float32", "_Float32_t"),
                            Item::Typedef("_Float64", "_Float64_t"),
                            Item::Typedef("_Float32x", "_Float32x_t"),
                            Item::Typedef("_Float64x", "_Float64x_t"),
                        ] },
                    ], ""),
                    Item::Typedef("_Float128", "_Float128_t"),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment("/* ilogb and llogb results */"),
            Item::Consts(&[
                ("FP_ILOGB0", V::Txt("(-2147483647 - 1)")),
                ("FP_ILOGBNAN", V::Txt("(-2147483647 - 1)")),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MATH_EXT", items: &[
                    Item::Consts(&[
                        ("FP_LLOGB0", V::Txt("(-0x7fffffffffffffffL - 1)")),
                        ("FP_LLOGBNAN", V::Txt("(-0x7fffffffffffffffL - 1)")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment("/* fpclassify results */"),
            Item::Consts(&[
                ("FP_NAN", V::Dec(0)),
                ("FP_INFINITE", V::Dec(1)),
                ("FP_ZERO", V::Dec(2)),
                ("FP_SUBNORMAL", V::Dec(3)),
                ("FP_NORMAL", V::Dec(4)),
            ]),
            Item::Blank,
            Item::Comment("/* The compiler's fused multiply-add is hardware only with -mfma; it says so */"),
            Item::Gate(&[
                Branch { head: "ifdef __FP_FAST_FMA", items: &[
                    Item::Consts(&[
                        ("FP_FAST_FMA", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef __FP_FAST_FMAF", items: &[
                    Item::Consts(&[
                        ("FP_FAST_FMAF", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment("/* Error handling: errno is set and the exception flags are raised */"),
            Item::Consts(&[
                ("MATH_ERRNO", V::Dec(1)),
                ("MATH_ERREXCEPT", V::Dec(2)),
            ]),
            Item::Gate(&[
                Branch { head: "ifdef __FAST_MATH__", items: &[
                    Item::Consts(&[
                        ("math_errhandling", V::Dec(0)),
                    ]),
                ] },
                Branch { head: "else", items: &[
                    Item::Consts(&[
                        ("math_errhandling", V::Txt("(MATH_ERRNO | MATH_ERREXCEPT)")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment("/* Classification and comparison macros (GCC builtins: inline, no library call) */"),
            Item::Raw(Reason::StdMacro, "#define signbit(x) __builtin_signbit (x)"),
            Item::Comment("/* With -fsignaling-nans (__SUPPORT_SNAN__) the builtins would raise Invalid on a signalling NaN (GCC bug 66462): use the library functions, chosen by type */"),
            Item::Gate(&[
                // clang: glibc uses the builtins whatever __SUPPORT_SNAN__ says (its condition: GCC 4.4 without
                // __SUPPORT_SNAN__, or clang 2.8 / 3.7 for isinf)
                Branch { head: "if defined __SUPPORT_SNAN__ && !defined __clang__", items: &[
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_MATH_FLOATN && __HAVE_FLOATN_NOT_TYPEDEF", items: &[
                            Item::Raw(Reason::Generic, r#"# define __MATH_TG(x, func, args) _Generic ((x), float: func ## f args, _Float32: func ## f args, default: func args, \
                                   long double: func ## l args, _Float64x: func ## l args, _Float128: func ## f128 args)"#),
                        ] },
                        // clang: _Float32 and _Float64x are typedefs of float and long double (bits/floatn.h), which a _Generic
                        // may not name twice; _Float128 (__float128) is a type of its own
                        Branch { head: "elif defined __RLIBC_MATH_FLOATN", items: &[
                            Item::Raw(Reason::Generic, r#"# define __MATH_TG(x, func, args) _Generic ((x), float: func ## f args, default: func args, \
                                   long double: func ## l args, _Float128: func ## f128 args)"#),
                        ] },
                        Branch { head: "else", items: &[
                            Item::Raw(Reason::Generic, "# define __MATH_TG(x, func, args) _Generic ((x), float: func ## f args, default: func args, long double: func ## l args)"),
                        ] },
                    ], ""),
                    Item::Raw(Reason::StdMacro, "# define fpclassify(x) __MATH_TG ((x), __fpclassify, (x))"),
                    Item::Raw(Reason::StdMacro, "# define isfinite(x) __MATH_TG ((x), __finite, (x))"),
                    Item::Raw(Reason::StdMacro, "# define isnormal(x) (fpclassify (x) == FP_NORMAL)"),
                    Item::Raw(Reason::StdMacro, "# define isnan(x) __MATH_TG ((x), __isnan, (x))"),
                    Item::Raw(Reason::StdMacro, "# define isinf(x) __MATH_TG ((x), __isinf, (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::StdMacro, "# define fpclassify(x) __builtin_fpclassify (FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, x)"),
                    Item::Raw(Reason::StdMacro, "# define isfinite(x) __builtin_isfinite (x)"),
                    Item::Raw(Reason::StdMacro, "# define isnormal(x) __builtin_isnormal (x)"),
                    Item::Raw(Reason::StdMacro, "# define isnan(x) __builtin_isnan (x)"),
                    Item::Raw(Reason::StdMacro, "# define isinf(x) __builtin_isinf_sign (x)"),
                ] },
            ], ""),
            // as glibc 2.43: the comparison builtins for GCC; for clang (and other compilers) glibc's generic forms, which
            // evaluate each argument once and compare only ordered values (isunordered checks both operands first)
            Item::Gate(&[
                Branch { head: "if __GNUC_PREREQ (3, 1) && !defined __clang__", items: &[
                    Item::Raw(Reason::StdMacro, "# define isgreater(x, y) __builtin_isgreater (x, y)"),
                    Item::Raw(Reason::StdMacro, "# define isgreaterequal(x, y) __builtin_isgreaterequal (x, y)"),
                    Item::Raw(Reason::StdMacro, "# define isless(x, y) __builtin_isless (x, y)"),
                    Item::Raw(Reason::StdMacro, "# define islessequal(x, y) __builtin_islessequal (x, y)"),
                    Item::Raw(Reason::StdMacro, "# define islessgreater(x, y) __builtin_islessgreater (x, y)"),
                    Item::Raw(Reason::StdMacro, "# define isunordered(x, y) __builtin_isunordered (x, y)"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::StdMacro, "# define isgreater(x, y) (__extension__ ({ __typeof__ (x) __x = (x); __typeof__ (y) __y = (y); !isunordered (__x, __y) && __x > __y; }))"),
                    Item::Raw(Reason::StdMacro, "# define isgreaterequal(x, y) (__extension__ ({ __typeof__ (x) __x = (x); __typeof__ (y) __y = (y); !isunordered (__x, __y) && __x >= __y; }))"),
                    Item::Raw(Reason::StdMacro, "# define isless(x, y) (__extension__ ({ __typeof__ (x) __x = (x); __typeof__ (y) __y = (y); !isunordered (__x, __y) && __x < __y; }))"),
                    Item::Raw(Reason::StdMacro, "# define islessequal(x, y) (__extension__ ({ __typeof__ (x) __x = (x); __typeof__ (y) __y = (y); !isunordered (__x, __y) && __x <= __y; }))"),
                    Item::Raw(Reason::StdMacro, "# define islessgreater(x, y) (__extension__ ({ __typeof__ (x) __x = (x); __typeof__ (y) __y = (y); !isunordered (__x, __y) && __x != __y; }))"),
                    Item::Raw(Reason::StdMacro, "# define isunordered(x, y) (__extension__ ({ __typeof__ (x) __u = (x); __typeof__ (y) __v = (y); __u != __v && (__u != __u || __v != __v); }))"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MATH_EXT", items: &[
                    Item::Raw(Reason::StdMacro, "# define iszero(x) (fpclassify (x) == FP_ZERO)"),
                    Item::Raw(Reason::StdMacro, "# define issubnormal(x) (fpclassify (x) == FP_SUBNORMAL)"),
                    Item::Comment("/* float, double and _Float128 values are always canonical; a long double has the x87 forms that are not */"),
                    Item::Raw(Reason::Generic, "# define iscanonical(x) _Generic ((x), long double: __iscanonicall (x), default: 1)"),
                    Item::Gate(&[
                        Branch { head: "if defined __RLIBC_MATH_FLOATN && __HAVE_FLOATN_NOT_TYPEDEF", items: &[
                            Item::Comment(r#"/* the _FloatN types are distinct types for _Generic: _Float32 is float's format, _Float64 and _Float32x are double's, _Float64x
   is long double's, _Float128 has its own functions */"#),
                            Item::Raw(Reason::Generic, r#"#  define issignaling(x) _Generic ((x), float: __issignalingf, double: __issignaling, long double: __issignalingl, \
                                   _Float32: __issignalingf, _Float64: __issignaling, _Float32x: __issignaling, \
                                   _Float64x: __issignalingl, _Float128: __issignalingf128) (x)"#),
                            Item::Raw(Reason::Generic, r#"#  define iseqsig(x, y) _Generic ((x) + (y), float: __iseqsigf, double: __iseqsig, long double: __iseqsigl, \
                                  _Float32: __iseqsigf, _Float64: __iseqsig, _Float32x: __iseqsig, \
                                  _Float64x: __iseqsigl, _Float128: __iseqsigf128) ((x), (y))"#),
                        ] },
                        Branch { head: "elif defined __RLIBC_MATH_FLOATN", items: &[
                            Item::Comment("/* clang: only _Float128 is a type of its own (the other _FloatN names are typedefs, bits/floatn.h) */"),
                            Item::Raw(Reason::Generic, r#"#  define issignaling(x) _Generic ((x), float: __issignalingf, double: __issignaling, long double: __issignalingl, \
                                   _Float128: __issignalingf128) (x)"#),
                            Item::Raw(Reason::Generic, r#"#  define iseqsig(x, y) _Generic ((x) + (y), float: __iseqsigf, double: __iseqsig, long double: __iseqsigl, \
                                  _Float128: __iseqsigf128) ((x), (y))"#),
                        ] },
                        Branch { head: "else", items: &[
                            Item::Raw(Reason::Generic, "#  define issignaling(x) _Generic ((x), float: __issignalingf, double: __issignaling, long double: __issignalingl) (x)"),
                            Item::Raw(Reason::Generic, "#  define iseqsig(x, y) _Generic ((x) + (y), float: __iseqsigf, double: __iseqsig, long double: __iseqsigl) ((x), (y))"),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::Comment("/* Constants (long double and _FloatN forms: GNU) */"),
            Item::Gate(&[
                Branch { head: "if defined __RLIBC_MATH_MISC || defined _XOPEN_SOURCE", items: &[
                    Item::Consts(&[
                        ("M_E", V::Txt("2.7182818284590452354 /* e */")),
                        ("M_LOG2E", V::Txt("1.4426950408889634074 /* log_2 e */")),
                        ("M_LOG10E", V::Txt("0.43429448190325182765 /* log_10 e */")),
                        ("M_LN2", V::Txt("0.69314718055994530942 /* log_e 2 */")),
                        ("M_LN10", V::Txt("2.30258509299404568402 /* log_e 10 */")),
                        ("M_PI", V::Txt("3.14159265358979323846 /* pi */")),
                        ("M_PI_2", V::Txt("1.57079632679489661923 /* pi/2 */")),
                        ("M_PI_4", V::Txt("0.78539816339744830962 /* pi/4 */")),
                        ("M_1_PI", V::Txt("0.31830988618379067154 /* 1/pi */")),
                        ("M_2_PI", V::Txt("0.63661977236758134308 /* 2/pi */")),
                        ("M_2_SQRTPI", V::Txt("1.12837916709551257390 /* 2/sqrt(pi) */")),
                        ("M_SQRT2", V::Txt("1.41421356237309504880 /* sqrt(2) */")),
                        ("M_SQRT1_2", V::Txt("0.70710678118654752440 /* 1/sqrt(2) */")),
                        ("MAXFLOAT", V::Txt("3.40282347e+38F")),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_MATH_GNU", items: &[
                    Item::Consts(&[
                        ("M_El", V::Txt("2.718281828459045235360287471352662498L")),
                        ("M_LOG2El", V::Txt("1.442695040888963407359924681001892137L")),
                        ("M_LOG10El", V::Txt("0.434294481903251827651128918916605082L")),
                        ("M_LN2l", V::Txt("0.693147180559945309417232121458176568L")),
                        ("M_LN10l", V::Txt("2.302585092994045684017991454684364208L")),
                        ("M_PIl", V::Txt("3.141592653589793238462643383279502884L")),
                        ("M_PI_2l", V::Txt("1.570796326794896619231321691639751442L")),
                        ("M_PI_4l", V::Txt("0.785398163397448309615660845819875721L")),
                        ("M_1_PIl", V::Txt("0.318309886183790671537767526745028724L")),
                        ("M_2_PIl", V::Txt("0.636619772367581343075535053490057448L")),
                        ("M_2_SQRTPIl", V::Txt("1.128379167095512573896158903121545172L")),
                        ("M_SQRT2l", V::Txt("1.414213562373095048801688724209698079L")),
                        ("M_SQRT1_2l", V::Txt("0.707106781186547524400844362104849039L")),
                        ("M_Ef", V::Txt("2.7182818284590452354f")),
                        ("M_LOG2Ef", V::Txt("1.4426950408889634074f")),
                        ("M_LOG10Ef", V::Txt("0.43429448190325182765f")),
                        ("M_LN2f", V::Txt("0.69314718055994530942f")),
                        ("M_LN10f", V::Txt("2.30258509299404568402f")),
                        ("M_PIf", V::Txt("3.14159265358979323846f")),
                        ("M_PI_2f", V::Txt("1.57079632679489661923f")),
                        ("M_PI_4f", V::Txt("0.78539816339744830962f")),
                        ("M_1_PIf", V::Txt("0.31830988618379067154f")),
                        ("M_2_PIf", V::Txt("0.63661977236758134308f")),
                        ("M_2_SQRTPIf", V::Txt("1.12837916709551257390f")),
                        ("M_SQRT2f", V::Txt("1.41421356237309504880f")),
                        ("M_SQRT1_2f", V::Txt("0.70710678118654752440f")),
                    ]),
                    Item::Gate(&[
                        Branch { head: "ifdef __RLIBC_MATH_FLOATN", items: &[
                            Item::Include("<bits/floatn.h>"),
                            Item::Consts(&[
                                ("M_Ef128", V::Txt("__f128 (2.718281828459045235360287471352662498)")),
                                ("M_LOG2Ef128", V::Txt("__f128 (1.442695040888963407359924681001892137)")),
                                ("M_LOG10Ef128", V::Txt("__f128 (0.434294481903251827651128918916605082)")),
                                ("M_LN2f128", V::Txt("__f128 (0.693147180559945309417232121458176568)")),
                                ("M_LN10f128", V::Txt("__f128 (2.302585092994045684017991454684364208)")),
                                ("M_PIf128", V::Txt("__f128 (3.141592653589793238462643383279502884)")),
                                ("M_PI_2f128", V::Txt("__f128 (1.570796326794896619231321691639751442)")),
                                ("M_PI_4f128", V::Txt("__f128 (0.785398163397448309615660845819875721)")),
                                ("M_1_PIf128", V::Txt("__f128 (0.318309886183790671537767526745028724)")),
                                ("M_2_PIf128", V::Txt("__f128 (0.636619772367581343075535053490057448)")),
                                ("M_2_SQRTPIf128", V::Txt("__f128 (1.128379167095512573896158903121545172)")),
                                ("M_SQRT2f128", V::Txt("__f128 (1.414213562373095048801688724209698079)")),
                                ("M_SQRT1_2f128", V::Txt("__f128 (0.707106781186547524400844362104849039)")),
                                ("M_Ef32", V::Txt("__f32 (2.718281828459045235360287471352662498)")),
                                ("M_LOG2Ef32", V::Txt("__f32 (1.442695040888963407359924681001892137)")),
                                ("M_LOG10Ef32", V::Txt("__f32 (0.434294481903251827651128918916605082)")),
                                ("M_LN2f32", V::Txt("__f32 (0.693147180559945309417232121458176568)")),
                                ("M_LN10f32", V::Txt("__f32 (2.302585092994045684017991454684364208)")),
                                ("M_PIf32", V::Txt("__f32 (3.141592653589793238462643383279502884)")),
                                ("M_PI_2f32", V::Txt("__f32 (1.570796326794896619231321691639751442)")),
                                ("M_PI_4f32", V::Txt("__f32 (0.785398163397448309615660845819875721)")),
                                ("M_1_PIf32", V::Txt("__f32 (0.318309886183790671537767526745028724)")),
                                ("M_2_PIf32", V::Txt("__f32 (0.636619772367581343075535053490057448)")),
                                ("M_2_SQRTPIf32", V::Txt("__f32 (1.128379167095512573896158903121545172)")),
                                ("M_SQRT2f32", V::Txt("__f32 (1.414213562373095048801688724209698079)")),
                                ("M_SQRT1_2f32", V::Txt("__f32 (0.707106781186547524400844362104849039)")),
                                ("M_Ef64", V::Txt("__f64 (2.718281828459045235360287471352662498)")),
                                ("M_LOG2Ef64", V::Txt("__f64 (1.442695040888963407359924681001892137)")),
                                ("M_LOG10Ef64", V::Txt("__f64 (0.434294481903251827651128918916605082)")),
                                ("M_LN2f64", V::Txt("__f64 (0.693147180559945309417232121458176568)")),
                                ("M_LN10f64", V::Txt("__f64 (2.302585092994045684017991454684364208)")),
                                ("M_PIf64", V::Txt("__f64 (3.141592653589793238462643383279502884)")),
                                ("M_PI_2f64", V::Txt("__f64 (1.570796326794896619231321691639751442)")),
                                ("M_PI_4f64", V::Txt("__f64 (0.785398163397448309615660845819875721)")),
                                ("M_1_PIf64", V::Txt("__f64 (0.318309886183790671537767526745028724)")),
                                ("M_2_PIf64", V::Txt("__f64 (0.636619772367581343075535053490057448)")),
                                ("M_2_SQRTPIf64", V::Txt("__f64 (1.128379167095512573896158903121545172)")),
                                ("M_SQRT2f64", V::Txt("__f64 (1.414213562373095048801688724209698079)")),
                                ("M_SQRT1_2f64", V::Txt("__f64 (0.707106781186547524400844362104849039)")),
                                ("M_Ef32x", V::Txt("__f32x (2.718281828459045235360287471352662498)")),
                                ("M_LOG2Ef32x", V::Txt("__f32x (1.442695040888963407359924681001892137)")),
                                ("M_LOG10Ef32x", V::Txt("__f32x (0.434294481903251827651128918916605082)")),
                                ("M_LN2f32x", V::Txt("__f32x (0.693147180559945309417232121458176568)")),
                                ("M_LN10f32x", V::Txt("__f32x (2.302585092994045684017991454684364208)")),
                                ("M_PIf32x", V::Txt("__f32x (3.141592653589793238462643383279502884)")),
                                ("M_PI_2f32x", V::Txt("__f32x (1.570796326794896619231321691639751442)")),
                                ("M_PI_4f32x", V::Txt("__f32x (0.785398163397448309615660845819875721)")),
                                ("M_1_PIf32x", V::Txt("__f32x (0.318309886183790671537767526745028724)")),
                                ("M_2_PIf32x", V::Txt("__f32x (0.636619772367581343075535053490057448)")),
                                ("M_2_SQRTPIf32x", V::Txt("__f32x (1.128379167095512573896158903121545172)")),
                                ("M_SQRT2f32x", V::Txt("__f32x (1.414213562373095048801688724209698079)")),
                                ("M_SQRT1_2f32x", V::Txt("__f32x (0.707106781186547524400844362104849039)")),
                                ("M_Ef64x", V::Txt("__f64x (2.718281828459045235360287471352662498)")),
                                ("M_LOG2Ef64x", V::Txt("__f64x (1.442695040888963407359924681001892137)")),
                                ("M_LOG10Ef64x", V::Txt("__f64x (0.434294481903251827651128918916605082)")),
                                ("M_LN2f64x", V::Txt("__f64x (0.693147180559945309417232121458176568)")),
                                ("M_LN10f64x", V::Txt("__f64x (2.302585092994045684017991454684364208)")),
                                ("M_PIf64x", V::Txt("__f64x (3.141592653589793238462643383279502884)")),
                                ("M_PI_2f64x", V::Txt("__f64x (1.570796326794896619231321691639751442)")),
                                ("M_PI_4f64x", V::Txt("__f64x (0.785398163397448309615660845819875721)")),
                                ("M_1_PIf64x", V::Txt("__f64x (0.318309886183790671537767526745028724)")),
                                ("M_2_PIf64x", V::Txt("__f64x (0.636619772367581343075535053490057448)")),
                                ("M_2_SQRTPIf64x", V::Txt("__f64x (1.128379167095512573896158903121545172)")),
                                ("M_SQRT2f64x", V::Txt("__f64x (1.414213562373095048801688724209698079)")),
                                ("M_SQRT1_2f64x", V::Txt("__f64x (0.707106781186547524400844362104849039)")),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
        ]},
    ],
};
