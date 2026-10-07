#ifndef _RLIBC_CDEFS_H
#define _RLIBC_CDEFS_H 1
#define __ASMNAME(cname) __ASMNAME2 (__USER_LABEL_PREFIX__, cname)
#define __ASMNAME2(prefix,cname) __STRING (prefix) cname
#define __BEGIN_DECLS 
#define __COLD __attribute__ ((__cold__))
#define __CONCAT(x,y) x ## y
#define __END_DECLS 
#define __GLIBC_USE(F) __GLIBC_USE_ ## F
#define __GLIBC_USE_IEC_60559_BFP_EXT 1
#define __GLIBC_USE_IEC_60559_BFP_EXT_C23 1
#define __GLIBC_USE_IEC_60559_EXT 1
#define __GLIBC_USE_IEC_60559_FUNCS_EXT 1
#define __GLIBC_USE_IEC_60559_FUNCS_EXT_C23 1
#define __GLIBC_USE_IEC_60559_TYPES_EXT 1
#define __GLIBC_USE_LIB_EXT2 1
#define __GNUC_PREREQ(maj,min) ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#define __HAVE_GENERIC_SELECTION 1
#define __KERNEL_STRICT_NAMES 
#define __LDBL_REDIR(name,proto) name proto
#define __LDBL_REDIR1(name,proto,alias) name proto
#define __LDBL_REDIR1_NTH(name,proto,alias) name proto __THROW
#define __LDBL_REDIR2_DECL(name) 
#define __LDBL_REDIR_DECL(name) 
#define __LDBL_REDIR_NTH(name,proto) name proto __THROW
#define __LDOUBLE_REDIRECTS_TO_FLOAT128_ABI 0
#define __LEAF , __leaf__
#define __LEAF_ATTR __attribute__ ((__leaf__))
#define __NTH(fct) __attribute__ ((__nothrow__ __LEAF)) fct
#define __NTHNL(fct) __attribute__ ((__nothrow__)) fct
#define __P(args) args
#define __PMT(args) args
#define __REDIRECT(name,proto,alias) name proto __asm__ (__ASMNAME (#alias))
#define __REDIRECT_FORTIFY __REDIRECT
#define __REDIRECT_FORTIFY_NTH __REDIRECT_NTH
#define __REDIRECT_LDBL(name,proto,alias) __REDIRECT (name, proto, alias)
#define __REDIRECT_NTH(name,proto,alias) name proto __asm__ (__ASMNAME (#alias)) __THROW
#define __REDIRECT_NTHNL(name,proto,alias) name proto __asm__ (__ASMNAME (#alias)) __THROWNL
#define __REDIRECT_NTH_LDBL(name,proto,alias) __REDIRECT_NTH (name, proto, alias)
#define __STRING(x) #x
#define __SYSCALL_WORDSIZE 64
#define __THROW __attribute__ ((__nothrow__ __LEAF))
#define __THROWNL __attribute__ ((__nothrow__))
#define __TIMESIZE __WORDSIZE
#define __WORDSIZE 64
#define __WORDSIZE_TIME64_COMPAT32 1
#define __always_inline __inline __attribute__ ((__always_inline__))
#define __attr_access(x) __attribute__ ((__access__ x))
#define __attr_access_none(argno) __attribute__ ((__access__ (__none__, argno)))
#define __attr_dealloc(dealloc,argno) __attribute__ ((__malloc__ (dealloc, argno)))
#define __attr_dealloc_free __attr_dealloc (__builtin_free, 1)
#define __attribute_alloc_align__(param) __attribute__ ((__alloc_align__ param))
#define __attribute_alloc_size__(params) __attribute__ ((__alloc_size__ params))
#define __attribute_artificial__ __attribute__ ((__artificial__))
#define __attribute_const__ __attribute__ ((__const__))
#define __attribute_copy__(arg) __attribute__ ((__copy__ (arg)))
#define __attribute_deprecated__ __attribute__ ((__deprecated__))
#define __attribute_deprecated_msg__(msg) __attribute__ ((__deprecated__ (msg)))
#define __attribute_format_arg__(x) __attribute__ ((__format_arg__ (x)))
#define __attribute_format_strfmon__(a,b) __attribute__ ((__format__ (__strfmon__, a, b)))
#define __attribute_malloc__ __attribute__ ((__malloc__))
#define __attribute_maybe_unused__ __attribute__ ((__unused__))
#define __attribute_noinline__ __attribute__ ((__noinline__))
#define __attribute_nonnull__(params) __attribute__ ((__nonnull__ params))
#define __attribute_nonstring__ __attribute__ ((__nonstring__))
#define __attribute_overloadable__ 
#define __attribute_pure__ __attribute__ ((__pure__))
#define __attribute_returns_twice__ __attribute__ ((__returns_twice__))
#define __attribute_struct_may_alias__ __attribute__ ((__may_alias__))
#define __attribute_used__ __attribute__ ((__used__))
#define __attribute_warn_unused_result__ __attribute__ ((__warn_unused_result__))
#define __bos(ptr) __builtin_object_size (ptr, __USE_FORTIFY_LEVEL > 1)
#define __bos0(ptr) __builtin_object_size (ptr, 0)
#define __errordecl(name,msg) extern void name (void) __attribute__((__error__ (msg)))
#define __extern_always_inline extern __always_inline __attribute__ ((__gnu_inline__))
#define __extern_inline extern __inline __attribute__ ((__gnu_inline__))
#define __flexarr []
#define __fortified_attr_access(a,o,s) __attr_access ((a, o, s))
#define __fortify_function __extern_always_inline __attribute_artificial__
#define __glibc_c99_flexarr_available 1
#define __glibc_clang_prereq(maj,min) 0
#define __glibc_const_generic(PTR,CTYPE,CALL) _Generic (0 ? (PTR) : (void *) 1, const void *: (CTYPE) (CALL), default: CALL)
#define __glibc_has_attribute(attr) __has_attribute (attr)
#define __glibc_has_builtin(name) __has_builtin (name)
#define __glibc_has_extension(ext) __has_extension (ext)
#define __glibc_likely(cond) __builtin_expect ((cond), 1)
#define __glibc_macro_warning(message) __glibc_macro_warning1 (GCC warning message)
#define __glibc_macro_warning1(message) _Pragma (#message)
#define __glibc_objsize(__o) __bos (__o)
#define __glibc_objsize0(__o) __bos0 (__o)
#define __glibc_unlikely(cond) __builtin_expect ((cond), 0)
#define __nonnull(params) __attribute_nonnull__ (params)
#define __ptr_t void *
#define __restrict_arr __restrict
#define __returns_nonnull __attribute__ ((__returns_nonnull__))
#define __stub___compat_bdflush 
#define __stub_chflags 
#define __stub_fchflags 
#define __stub_gtty 
#define __stub_revoke 
#define __stub_setlogin 
#define __stub_sigreturn 
#define __stub_stty 
#define __va_arg_pack() __builtin_va_arg_pack ()
#define __va_arg_pack_len() __builtin_va_arg_pack_len ()
#define __warnattr(msg) __attribute__((__warning__ (msg)))
#define __wur 

#endif
