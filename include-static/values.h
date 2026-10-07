#ifndef _VALUES_H
#define _VALUES_H 1
#include <features.h>
#include <limits.h>
#include <float.h>
#ifdef __cplusplus
extern "C" {
#endif
#define BITSPERBYTE CHAR_BIT
#define CHARBITS _TYPEBITS (char)
#define DMAXEXP DBL_MAX_EXP
#define DMINEXP DBL_MIN_EXP
#define DOUBLEBITS _TYPEBITS (double)
#define FLOATBITS _TYPEBITS (float)
#define FMAXEXP FLT_MAX_EXP
#define FMINEXP FLT_MIN_EXP
#define HIBITL MINLONG
#define HIBITS MINSHORT
#define INTBITS _TYPEBITS (int)
#define LONGBITS _TYPEBITS (long int)
#define MAXDOUBLE DBL_MAX
#define MAXFLOAT FLT_MAX
#define MAXINT INT_MAX
#define MAXLONG LONG_MAX
#define MAXSHORT SHRT_MAX
#define MINDOUBLE DBL_MIN
#define MINFLOAT FLT_MIN
#define MININT INT_MIN
#define MINLONG LONG_MIN
#define MINSHORT SHRT_MIN
#define PTRBITS _TYPEBITS (char *)
#define SHORTBITS _TYPEBITS (short int)
#define _TYPEBITS(type) (sizeof (type) * CHAR_BIT)
#ifdef __cplusplus
}
#endif
#endif
