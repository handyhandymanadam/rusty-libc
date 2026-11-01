//! stdlib.h (the parts that are not malloc): conversions, sorting, random numbers, the environment,
//! temporary files, running commands.
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]
// BRIEF-UNSAFE U2: every unsafe block holds one unsafe operation and says why it is sound. What stays unsafe, by module:
// the C entry points' pointer conversions (one per argument: C strings to ZStr/&CStr, buffers to slices, out-parameters);
// zstr.rs (reading a NUL-terminated string through its invariant), cmem.rs (free/realloc and the C-heap views), sys.rs
// (one raw system call per function); num.rs (the MXCSR save/restore around the 16-19 digit quick path, and the naked
// x87/xmm0 returns of strtold/strtof128 with their 16-byte result slot); sort.rs (each call of the C comparator, the
// scratch buffer view); rand.rs (random_data's state array, which is caller memory behind raw pointers in glibc's layout,
// and the drand48 pointer arguments); env.rs (environ and the slots of the array it points to, entry strings, the new
// array's allocation); misc.rs (posix_spawn with its C argument vector, the cancellation cleanup registration, the
// environment block, getsubopt's in-place cut, free).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

mod cmem; // the allocator calls without preconditions, made safe; CVec
mod sys; // raw system calls behind one audited function each
pub mod zstr; // ZStr: a cursor over a NUL-terminated string of unknown length
pub mod num; // abs, div, atoi, strtol and strtod families
pub mod grouped; // the thousands-separator `group` argument of __strtod_internal & co.
pub mod sort; // qsort, qsort_r, bsearch
pub mod rand; // rand, random, drand48 families, arc4random
pub mod env; // getenv, setenv, unsetenv, putenv, clearenv
pub mod stdbit; // stdbit.h: stdc_leading_zeros ... stdc_bit_ceil (C23)
pub mod misc; // system, mkstemp family, realpath, getloadavg, pty functions, getsubopt, ...

/// One lock for tests that touch global state (errno, the environment, random state).
#[cfg(test)]
pub(crate) static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
