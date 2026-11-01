//! strfry (string.h): randomize a string in place.
//!
//! glibc seeds a private `random_r` generator with the time and the process id on the first call,
//! then walks the string swapping each character with a random one (every position `i` is swapped
//! with `random % len`). The result is a permutation of the characters; nothing more is promised.
use core::ffi::c_char;
use rusty_libc_core::lock::Locked;
use rusty_libc_stdlib::rand::{RandomData, initstate_r, random_r};

/// The private generator: glibc's `static int init; static struct random_data rdata; static char state[32]`.
struct Fry {
    init: bool,
    rdata: RandomData,
    state: [c_char; 32],
}

// SAFETY: the raw pointers in `rdata` point into `state` of the same value, which lives in a static and is only reached
// through `FRY`'s lock; nothing thread-local is kept.
unsafe impl Send for Fry {}

const NULL_RDATA: RandomData = RandomData { fptr: core::ptr::null_mut(), rptr: core::ptr::null_mut(), state: core::ptr::null_mut(), rand_type: 0, rand_deg: 0, rand_sep: 0, end_ptr: core::ptr::null_mut() };
static FRY: Locked<Fry> = Locked::new(Fry { init: false, rdata: NULL_RDATA, state: [0; 32] });

/// Randomize the bytes of `s` in place (the safe core of `strfry`): every position `i` is swapped with `random % len`.
pub fn strfry_bytes(s: &mut [u8]) {
    FRY.with(|f| {
        if !f.init {
            let mut ts = [0i64; 2];
            // SAFETY: `ts` is a writable `struct timespec` (two 64-bit words).
            unsafe { rusty_libc_core::vdso::clock_gettime_raw(0, ts.as_mut_ptr().cast()) };
            let pid = rusty_libc_core::unistd::getpid() as u32;
            // SAFETY: `state` has the 32 bytes passed and `rdata` is writable; both live in the static, so the pointers
            // initstate_r stores in `rdata` stay valid.
            unsafe { initstate_r((ts[0] as u32) ^ pid, f.state.as_mut_ptr(), 32, &raw mut f.rdata) };
            f.init = true;
        }
        let len = s.len();
        for i in 0..len {
            let mut j: i32 = 0;
            // SAFETY: `rdata` was set up by initstate_r above (its pointers point into `state`); `j` is writable.
            unsafe { random_r(&raw mut f.rdata, &mut j) };
            s.swap(i, (j as usize) % len);
        }
    });
}

/// Randomize the characters of `string` (up to its NUL); returns `string`.
///
/// # Safety
/// `string` is a writable C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfry(string: *mut c_char) -> *mut c_char {
    // SAFETY: `string` is a C string (caller's contract).
    let n = unsafe { rusty_libc_core::ffi::cstr_len(string) };
    // SAFETY: its `n` bytes before the NUL are writable and not otherwise accessed during the call.
    strfry_bytes(unsafe { rusty_libc_core::ffi::bytes_mut(string.cast(), n) });
    string
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn strfry_permutes() {
        let mut buf = *b"the quick brown fox jumps over the lazy dog\0";
        let mut before = buf;
        unsafe { assert_eq!(strfry(buf.as_mut_ptr().cast()), buf.as_mut_ptr().cast()) };
        assert_eq!(buf[43], 0);
        before[..43].sort();
        let mut after = buf;
        after[..43].sort();
        assert_eq!(before, after);
        assert_ne!(&buf[..43], b"the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn strfry_short_strings() {
        let mut e = *b"\0";
        unsafe { strfry(e.as_mut_ptr().cast()) };
        assert_eq!(e, *b"\0");
        let mut one = *b"x\0";
        unsafe { strfry(one.as_mut_ptr().cast()) };
        assert_eq!(one, *b"x\0");
    }
}
