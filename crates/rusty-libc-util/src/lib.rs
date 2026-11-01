//! Library utilities that need no system calls of their own: getopt, user and group databases (files
//! only), fnmatch, libgen, search.h, err.h, assert, auxiliary vector.
#![cfg_attr(not(test), no_std)]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]
// BRIEF-UNSAFE U2: every unsafe block holds one unsafe operation and says why it is sound. What stays unsafe, by module:
// the C entry points' pointer conversions (one per entry), the caller's data structures the C interfaces hand over
// (search.rs tree nodes, glob_t and wordexp_t vectors, C string vectors in pwd.rs), the caller's and the plug-in
// modules' functions (comparison/walk/free callbacks, errfunc and GLOB_ALTDIRFUNC, `_nss_*` functions), the C heap
// blocks (cmem.rs), raw system calls without a safe wrapper (getdents64, newfstatat, fcntl lock, alarm, readlink,
// ioctl, setgroups, writev, kill), C varargs (err.rs), the exported C variables (getopt and error.h globals, the
// program name), inline assembly (cpuid, xgetbv, the signal restorer) and the stdio stream calls.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

mod cmem; // the allocator calls without preconditions, made safe
pub mod getopt; // helper C
pub mod pwd; // helper C (pwd.h, grp.h, shadow.h, ttyent-free parts)
pub mod fnmatch; // helper C
pub mod glob; // glob.h (with fnmatch)
pub mod wordexp; // wordexp.h (uses glob, fnmatch and the passwd files)
pub mod libgen; // helper C
pub mod search; // helper C
pub mod err; // helper C (err.h, error.h, assert)
pub mod auxv; // helper C
pub mod strfry; // strfry
pub mod cpuid; // __x86_get_cpuid_feature_leaf (sys/platform/x86.h)

/// One lock for tests that touch global state.
#[cfg(test)]
pub(crate) static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod search_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod err_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod testutil;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod getopt_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod fnmatch_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod pwd_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod glob_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod wordexp_tests;
