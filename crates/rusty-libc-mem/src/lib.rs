//! string.h and strings.h: memory and string functions, C ABI, raw pointers.
//! Written from the C standard, POSIX and observed glibc behaviour (see SYMBOLS.csv).
//! `no_builtins` stops the compiler turning these loops back into calls to themselves.
//!
//! Unsafe code (BRIEF-UNSAFE.md U2; U3 documents it further). Every unsafe block holds one unsafe operation and says why
//! it holds (denied below). What stays unsafe, and why:
//! - The exported C functions take raw pointers (C ABI); most hot ones are naked functions whose AVX2 fast path is
//!   hand-written assembly (`simd::avx2_front!`), with the dispatch slots (`simd::slot_table!`) and resolvers.
//! - The vector kernels (`mem`, `str`, `search`): unaligned and aligned loads and stores through the caller's pointers.
//!   String scans read whole vectors past the terminator but never past its page (the page rule in `str`); copies and
//!   fills access whole vectors at offsets inside the buffer (overlapping head and tail stores). Safe slices would cost
//!   bounds checks and, worse, change the code layout these functions were tuned for (a memcmp written over arrays took
//!   1.13x the time for small sizes with the same instructions), so the kernels keep their statement order and their
//!   machine code.
//! - `simd::Vector`: a vector value proves its instruction set (token pattern), so compare, mask and the other value
//!   operations are safe; the constructors, loads and stores stay unsafe.
//! - CPU detection (`xgetbv`), the large-copy streaming stores, `explicit_bzero`'s compiler barrier.
//!
//! Safe Rust API on slices and C strings: `swab_bytes`, `memfrob_bytes`, `strverscmp_cstr`.
// `#[rustc_align(64)]` on the hot entry points: a naked function is otherwise placed at 4-byte alignment (the
// -align-all-functions option does not reach it), and an entry in the last bytes of a 64-byte line costs a cycle in small calls.
#![feature(fn_align)]
#![cfg_attr(not(test), no_std)]
#![no_builtins]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

mod mem;
pub mod simd;
mod search;
mod slices;
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
    (STRPBRK, resolve_strpbrk, crate::str::strpbrk_sse2, crate::str::strpbrk_avx2),
    (STRSTR, resolve_strstr, crate::search::strstr_sse2, crate::search::strstr_avx2),
    (MEMMEM, resolve_memmem, crate::search::memmem_sse2, crate::search::memmem_avx2),
}

pub use mem::*;
pub use search::*;
pub use slices::*;
pub use str::*;

#[cfg(test)]
mod tests;

/// glibc's `__`-prefixed strong aliases (`__strcoll_l` for `strcoll_l`, ...) that libstdc++ and other compiled objects
/// import: a function that is one tail jump to the real one, so any signature (also an x87 result) passes through.
/// Place it next to the real function; it is exported with the crate's `export` feature like the real one. Every function
/// is its own object in the static library, so a program pulls in only the aliases it uses.
#[macro_export]
macro_rules! tail_alias {
    ($alias:ident => $real:path) => {
        /// # Safety
        /// As the function it jumps to.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $alias() {
            core::arch::naked_asm!("jmp {f}", f = sym $real)
        }
    };
}
