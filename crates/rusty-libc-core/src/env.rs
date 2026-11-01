//! The process environment: `environ` and `getenv`.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::c_char;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering, fence};

// SAFETY: `environ` is the C library's `char **environ` (defined by the startup code's assembly, or by the host libc in
// tests): one pointer-sized, pointer-aligned word. It is declared as an `AtomicPtr`, which has the same size and alignment
// as `*mut *mut c_char`, so every bit pattern C code stores in it is a valid value, and reading it while C code writes it
// is an atomic access rather than a data race on our side. An immutable extern static may change under us only inside an
// `UnsafeCell` (The Rust Reference p.163), which `AtomicPtr` is; hence `safe`: touching the word itself is safe, using
// the pointer it holds is not (RFC 3484, safe items in unsafe extern blocks).
unsafe extern "C" {
    /// The program's environment (set by the startup code, or by the host libc in tests).
    pub safe static environ: AtomicPtr<*mut c_char>;
}

/// The environment block: a NULL-terminated array of `NAME=value` strings.
///
/// # Safety
/// The environment must not be modified concurrently.
pub unsafe fn block() -> *mut *mut c_char {
    environ.load(Ordering::Relaxed)
}

/// Bumped by every store that moves entries of the environment array (unsetenv, clearenv): a lock-free `getenv` that finds
/// nothing checks it, and scans again when it changed while it looked (glibc's `__environ_counter` protocol).
pub static ENV_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The current value of `environ` (a relaxed atomic load).
///
/// # Safety
/// Reads the process-wide variable.
#[inline]
pub unsafe fn load_environ() -> *mut *mut c_char {
    environ.load(Ordering::Relaxed)
}

/// The value of `name` (no `=`), as a pointer into the environment, or NULL. Safe against a concurrent setenv, putenv or
/// unsetenv in another thread or a signal handler, like glibc's: the array is only ever extended in place or replaced by a
/// zero-filled copy, the strings are never freed, and a miss is repeated when an unsetenv moved entries during the scan.
/// (An empty `name` finds the first entry that starts with `=`; the C `getenv` refuses an empty name before it gets here.)
///
/// # Safety
/// `environ` is NULL or a NULL-terminated array of NUL-terminated strings (what C code may store in it; nothing here can
/// check it), whose entries are written only atomically or by the library's own environment functions.
pub unsafe fn getenv(name: &[u8]) -> *mut c_char {
    // The scan looks at one byte per entry: the first byte of `name` (for an empty name, the `=` that must follow it), as
    // glibc does; only an entry with that first byte goes on to the full comparison.
    let first = name.first().copied().unwrap_or(b'=');
    loop {
        let start = ENV_COUNTER.load(Ordering::Acquire);
        let mut e = environ.load(Ordering::Relaxed);
        if e.is_null() {
            return core::ptr::null_mut();
        }
        loop {
            // SAFETY: `e` is an entry of the NULL-terminated array (the scan stops at the NULL), aligned and live: the array
            // is never freed while it can be in use (caller's contract).
            let entry = unsafe { AtomicPtr::from_ptr(e) }.load(Ordering::Relaxed) as *const u8;
            if entry.is_null() {
                break;
            }
            // SAFETY: a non-NULL entry is a NUL-terminated string (caller's contract): its first byte is readable.
            if unsafe { *entry } == first {
                // the rest of the comparison stops at the first byte that differs; `name` has no NUL, so it never reads past
                // the string's NUL (byte 0 matched: a byte of `name`, or for an empty name the `=` checked below)
                let mut i = 1.min(name.len());
                loop {
                    // SAFETY: bytes 0..i of the string matched `name`, which has no NUL, so the string goes on at least to
                    // byte i (at worst its NUL), inside the same allocation.
                    let p = unsafe { entry.add(i) };
                    // SAFETY: `p` is a byte of the string (above).
                    let c = unsafe { *p };
                    if i == name.len() {
                        if c == b'=' {
                            // SAFETY: byte i is the `=`, so i + 1 is at most the string's NUL: inside the same allocation.
                            return unsafe { entry.add(i + 1) } as *mut c_char;
                        }
                        break;
                    }
                    if c != name[i] {
                        break;
                    }
                    i += 1;
                }
            }
            // SAFETY: `entry` was not NULL, so the array goes on past `e`.
            e = unsafe { e.add(1) };
        }
        // not found: a false miss is possible while unsetenv shuffles the entries
        fence(Ordering::Acquire);
        if ENV_COUNTER.load(Ordering::Acquire) == start {
            return core::ptr::null_mut();
        }
    }
}
