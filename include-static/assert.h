#include <features.h>
#undef assert
#undef assert_perror

#undef __ASSERT_VARIADIC
#if !defined __cplusplus && (defined __GNUC__ || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L))
# define __ASSERT_VARIADIC 1
#else
# define __ASSERT_VARIADIC 0
#endif

#ifdef NDEBUG
# define __ASSERT_VOID_CAST (void)
# if __ASSERT_VARIADIC
#  define assert(...) (__ASSERT_VOID_CAST (0))
# else
#  define assert(expr) (__ASSERT_VOID_CAST (0))
# endif
# define assert_perror(errnum) (__ASSERT_VOID_CAST (0))
#else
# ifndef _ASSERT_H_DECLS
#  define _ASSERT_H_DECLS
#  ifdef __cplusplus
extern "C" {
#  endif
extern void __assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) __attribute__((__noreturn__));
extern void __assert_perror_fail(int __errnum, const char *__file, unsigned int __line, const char *__function) __attribute__((__noreturn__));
extern void __assert(const char *__assertion, const char *__file, int __line) __attribute__((__noreturn__));
#  ifdef __cplusplus
}
#  endif
# endif
# undef __ASSERT_VOID_CAST
# if defined __cplusplus
#  define __ASSERT_VOID_CAST static_cast<void>
# else
#  define __ASSERT_VOID_CAST (void)
# endif
# undef __ASSERT_FUNCTION
# if defined __GNUC__
#  define __ASSERT_FUNCTION __extension__ __PRETTY_FUNCTION__
# elif defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
#  define __ASSERT_FUNCTION __func__
# else
#  define __ASSERT_FUNCTION ((const char *) 0)
# endif
# if __ASSERT_VARIADIC
#  define assert(...) \
    ((__VA_ARGS__) ? __ASSERT_VOID_CAST (0) : __assert_fail (#__VA_ARGS__, __FILE__, __LINE__, __ASSERT_FUNCTION))
# else
#  define assert(expr) \
    ((expr) ? __ASSERT_VOID_CAST (0) : __assert_fail (#expr, __FILE__, __LINE__, __ASSERT_FUNCTION))
# endif
# define assert_perror(errnum) \
    (!(errnum) ? __ASSERT_VOID_CAST (0) : __assert_perror_fail ((errnum), __FILE__, __LINE__, __ASSERT_FUNCTION))
#endif

#ifndef _ASSERT_H
# define _ASSERT_H 1
# if defined __STDC_VERSION__ && __STDC_VERSION__ >= 201112L && !defined __cplusplus && !defined __STDC_VERSION_ASSERT_H__
#  undef static_assert
#  define static_assert _Static_assert
# endif
#endif
