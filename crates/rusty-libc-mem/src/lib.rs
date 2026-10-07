#![no_std]
#![no_builtins]
#![allow(clippy::missing_safety_doc)]

mod mem;
mod simd;
mod search;
mod str;

simd::slot_table! {
    (MEMCPY, resolve_memcpy, crate::mem::memcpy_sse2, crate::mem::memcpy_avx2),
    (MEMMOVE, resolve_memmove, crate::mem::memmove_sse2, crate::mem::memmove_avx2),
    (MEMSET, resolve_memset, crate::mem::memset_sse2, crate::mem::memset_avx2),
    (MEMCMP, resolve_memcmp, crate::mem::memcmp_sse2, crate::mem::memcmp_avx2),
    (MEMCHR, resolve_memchr, crate::mem::memchr_sse2, crate::mem::memchr_avx2),
    (MEMRCHR, resolve_memrchr, crate::mem::memrchr_sse2, crate::mem::memrchr_avx2),
    (RAWMEMCHR, resolve_rawmemchr, crate::mem::rawmemchr_sse2, crate::mem::rawmemchr_avx2),
    (STRLEN, resolve_strlen, crate::str::strlen_sse2, crate::str::strlen_avx2),
    (STRNLEN, resolve_strnlen, crate::str::strnlen_sse2, crate::str::strnlen_avx2),
    (STRCPY, resolve_strcpy, crate::str::strcpy_sse2, crate::str::strcpy_avx2),
    (STPCPY, resolve_stpcpy, crate::str::stpcpy_sse2, crate::str::stpcpy_avx2),
    (STRCAT, resolve_strcat, crate::str::strcat_generic, crate::str::strcat_generic),
    (STRNCPY, resolve_strncpy, crate::str::strncpy_sse2, crate::str::strncpy_avx2),
    (STPNCPY, resolve_stpncpy, crate::str::stpncpy_sse2, crate::str::stpncpy_avx2),
    (STRCMP, resolve_strcmp, crate::str::strcmp_sse2, crate::str::strcmp_avx2),
    (STRNCMP, resolve_strncmp, crate::str::strncmp_sse2, crate::str::strncmp_avx2),
    (STRCASECMP, resolve_strcasecmp, crate::str::strcasecmp_sse2, crate::str::strcasecmp_avx2),
    (STRNCASECMP, resolve_strncasecmp, crate::str::strncasecmp_sse2, crate::str::strncasecmp_avx2),
    (STRCHRNUL, resolve_strchrnul, crate::str::strchrnul_sse2, crate::str::strchrnul_avx2),
    (STRCHR, resolve_strchr, crate::str::strchr_sse2, crate::str::strchr_avx2),
    (STRRCHR, resolve_strrchr, crate::str::strrchr_sse2, crate::str::strrchr_avx2),
    (STRSPN, resolve_strspn, crate::str::strspn_sse2, crate::str::strspn_avx2),
    (STRCSPN, resolve_strcspn, crate::str::strcspn_sse2, crate::str::strcspn_avx2),
    (STRSTR, resolve_strstr, crate::search::strstr_sse2, crate::search::strstr_avx2),
    (MEMMEM, resolve_memmem, crate::search::memmem_sse2, crate::search::memmem_avx2),
}

pub use mem::*;
pub use search::*;
pub use str::*;

