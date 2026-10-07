#ifndef _BITS_FLOATN_H
#define _BITS_FLOATN_H 1
#include <features.h>
#define __HAVE_FLOAT128 1
#define __HAVE_DISTINCT_FLOAT128 1
#define __HAVE_FLOAT64X 1
#define __HAVE_FLOAT64X_LONG_DOUBLE 1
#ifndef __ASSEMBLER__
# define __f128(x) x##f128
# define __CFLOAT128 _Complex _Float128
#endif
#include <bits/floatn-common.h>
#endif
