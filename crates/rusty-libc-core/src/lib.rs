//! rusty-libc-core: the Rust runtime. Plain Rust API with no C types in the way; the C face
//! (rusty-libc-cabi) wraps these. `no_std`, Linux x86_64 only.
#![cfg_attr(not(test), no_std)]
#![feature(thread_local)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod cleanup;
pub mod env;
pub mod errno;
pub mod fd;
pub mod ffi;
pub mod floatparse;
pub mod i18n;
pub mod pow5;
pub mod lock;
pub mod locale;
pub mod messages;
pub mod nscd;
pub mod nssent;
pub mod nssmod;
pub mod pages;
pub mod process;
pub mod signal;
pub mod spawn;
#[cfg(feature = "start")]
pub mod start;
#[cfg(feature = "shared")]
pub mod shared;
pub mod string;
/// Pointer-free string tables: one implementation, in the Rust face's rusty-libc-rs-core (FIXLIST #127).
pub use rusty_libc_rs_core::strtab;
pub mod sync_cell;
pub mod syscall;
pub mod thread_db;
pub mod tls;
pub mod tunables;
pub mod unistd;
pub mod vdso;
pub mod x87;

pub use errno::Errno;
pub use fd::{BorrowedFd, Fd};
pub use sync_cell::SyncCell;

/// Tunable `i` (the index in `tunables::LIST`) when the environment set it, as glibc's `TUNABLE_GET` with a callback (the
/// callback runs only for a tunable that was set): in libc.so.6 the loader's value (`__tunable_is_initialized` and
/// `__tunable_get_val`), in a static program what its start-up stored. A size or a 32-bit number, as the tunable's type.
pub fn tunable_set(i: usize) -> Option<i64> {
    #[cfg(feature = "shared")]
    {
        let (is_init, get_val): (usize, usize);
        // SAFETY: loads the GOT slot of a weak symbol (0 when the loader does not define it); register output only.
        unsafe { core::arch::asm!(".weak __tunable_is_initialized", "mov {0}, [rip + __tunable_is_initialized@GOTPCREL]", out(reg) is_init, options(nomem, nostack, preserves_flags)) };
        // SAFETY: as above.
        unsafe { core::arch::asm!(".weak __tunable_get_val", "mov {0}, [rip + __tunable_get_val@GOTPCREL]", out(reg) get_val, options(nomem, nostack, preserves_flags)) };
        if is_init == 0 || get_val == 0 {
            return None;
        }
        // SAFETY: the loader's `__tunable_is_initialized(id) -> bool` (glibc's GLIBC_PRIVATE signature).
        let is_init: unsafe extern "C" fn(u32) -> bool = unsafe { core::mem::transmute(is_init) };
        // SAFETY: the loader's `__tunable_get_val(id, valp, callback)`.
        let get_val: unsafe extern "C" fn(u32, *mut u8, usize) = unsafe { core::mem::transmute(get_val) };
        // SAFETY: `i` is an index of `tunables::LIST`, the loader's tunable ids.
        if !unsafe { is_init(i as u32) } {
            return None;
        }
        let mut v = 0u64;
        // SAFETY: the loader writes the tunable's value (at most 8 bytes) into the local `v`; no callback.
        unsafe { get_val(i as u32, (&raw mut v).cast(), 0) };
        Some(if tunables::num(i).ty == tunables::Ty::I32 { v as u32 as i32 as i64 } else { v as i64 })
    }
    #[cfg(not(feature = "shared"))]
    {
        tunables::stored(i)
    }
}

pub use rusty_libc_mem::tail_alias;
