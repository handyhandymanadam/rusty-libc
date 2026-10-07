#ifndef _BITS_FLOATN_COMMON_H
#define _BITS_FLOATN_COMMON_H 1
#include <features.h>
#define __HAVE_FLOAT16 0
#define __HAVE_FLOAT32 1
#define __HAVE_FLOAT64 1
#define __HAVE_FLOAT32X 1
#define __HAVE_FLOAT128X 0
#define __HAVE_DISTINCT_FLOAT16 __HAVE_FLOAT16
#define __HAVE_DISTINCT_FLOAT32 0
#define __HAVE_DISTINCT_FLOAT64 0
#define __HAVE_DISTINCT_FLOAT32X 0
#define __HAVE_DISTINCT_FLOAT64X 0
#define __HAVE_DISTINCT_FLOAT128X __HAVE_FLOAT128X
#define __HAVE_FLOAT128_UNLIKE_LDBL (__HAVE_DISTINCT_FLOAT128 && __LDBL_MANT_DIG__ != 113)
#if !defined __cplusplus
# define __HAVE_FLOATN_NOT_TYPEDEF 1
#else
# define __HAVE_FLOATN_NOT_TYPEDEF 0
#endif
#ifndef __ASSEMBLER__
# define __f32(x) x##f32
# define __f64(x) x##f64
# define __f32x(x) x##f32x
# define __f64x(x) x##f64x
# define __CFLOAT32 _Complex _Float32
# define __CFLOAT64 _Complex _Float64
# define __CFLOAT32X _Complex _Float32x
# define __CFLOAT64X _Complex _Float64x
#endif
#endif
