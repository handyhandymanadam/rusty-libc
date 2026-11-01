//! `__b64_ntop` and `__b64_pton`: the resolver's base-64 conversion (RFC 4648 alphabet, `=` padding), exported by glibc
//! (GLIBC_2.2.5) for programs such as tmux. Behaviour as the ISC resolver code that glibc ships: `__b64_pton` skips white
//! space, stops at the first `=`, insists on correct padding and zero bits after the last full byte, and counts only
//! (without writing) when `target` is NULL.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use core::ffi::{c_char, c_int, c_uchar};
use rusty_libc_core::ffi;

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

/// Encode `src` into `target` as base 64 followed by a NUL. Returns the length without the NUL, or -1 when `target` is too
/// small (the bytes written until then stay written, as in glibc).
pub fn ntop(src: &[u8], target: &mut [u8]) -> c_int {
    let targsize = target.len();
    let mut datalength = 0usize;
    let mut put = |c: u8| -> bool {
        if datalength >= targsize {
            return false;
        }
        target[datalength] = c;
        datalength += 1;
        true
    };
    let mut i = 0;
    while i + 3 <= src.len() {
        let (a, b, c) = (src[i], src[i + 1], src[i + 2]);
        i += 3;
        if !(put(BASE64[(a >> 2) as usize]) && put(BASE64[(((a & 3) << 4) | (b >> 4)) as usize]) && put(BASE64[(((b & 0xf) << 2) | (c >> 6)) as usize]) && put(BASE64[(c & 0x3f) as usize])) {
            return -1;
        }
    }
    let rest = src.len() - i;
    if rest != 0 {
        let a = src[i];
        let b = if rest == 2 { src[i + 1] } else { 0 };
        if !(put(BASE64[(a >> 2) as usize]) && put(BASE64[(((a & 3) << 4) | (b >> 4)) as usize])) {
            return -1;
        }
        let third = if rest == 1 { PAD } else { BASE64[((b & 0xf) << 2) as usize] };
        if !(put(third) && put(PAD)) {
            return -1;
        }
    }
    if datalength >= targsize {
        return -1;
    }
    target[datalength] = 0;
    datalength as c_int
}

/// Encode `srclength` bytes of `src` into `target` (NUL-terminated). Returns the length without the NUL, or -1 when
/// `targsize` is too small.
///
/// # Safety
/// `src` must be readable for `srclength` bytes and `target` writable for `targsize` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __b64_ntop(src: *const c_uchar, srclength: usize, target: *mut c_char, targsize: usize) -> c_int {
    // SAFETY: the caller's contract: `src` is readable for `srclength` bytes.
    let src = unsafe { ffi::bytes(src, srclength) };
    // SAFETY: the caller's contract: `target` is writable for `targsize` bytes (and is not `src`'s memory).
    let target = unsafe { ffi::bytes_mut(target.cast::<u8>(), targsize) };
    ntop(src, target)
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Decode the base-64 text `src` (the bytes of a C string, without its NUL) into `target`. Returns the number of bytes, or
/// -1 on bad input or when `target` is too small. With `None` only the length is computed. Bytes written before an error
/// stay written, as in glibc.
pub fn pton(src: &[u8], mut target: Option<&mut [u8]>) -> c_int {
    let targsize = target.as_ref().map_or(0, |t| t.len());
    // the C code reads the text up to its NUL: past the end of `src` is that NUL
    let at = |i: usize| src.get(i).copied().unwrap_or(0);
    let mut p = 0usize;
    let mut tarindex = 0usize;
    let mut state = 0u8;
    let mut ch;
    loop {
        ch = at(p);
        p += 1;
        if ch == 0 {
            break;
        }
        if is_space(ch) {
            continue;
        }
        if ch == PAD {
            break;
        }
        let Some(pos) = BASE64.iter().position(|&b| b == ch) else { return -1 };
        let pos = pos as u8;
        match state {
            0 => {
                if let Some(t) = target.as_deref_mut() {
                    if tarindex >= targsize {
                        return -1;
                    }
                    t[tarindex] = pos << 2;
                }
                state = 1;
            }
            1 => {
                if let Some(t) = target.as_deref_mut() {
                    if tarindex + 1 >= targsize {
                        return -1;
                    }
                    t[tarindex] |= pos >> 4;
                    t[tarindex + 1] = (pos & 0x0f) << 4;
                }
                tarindex += 1;
                state = 2;
            }
            2 => {
                if let Some(t) = target.as_deref_mut() {
                    if tarindex + 1 >= targsize {
                        return -1;
                    }
                    t[tarindex] |= pos >> 2;
                    t[tarindex + 1] = (pos & 0x03) << 6;
                }
                tarindex += 1;
                state = 3;
            }
            _ => {
                if let Some(t) = target.as_deref_mut() {
                    if tarindex >= targsize {
                        return -1;
                    }
                    t[tarindex] |= pos;
                }
                tarindex += 1;
                state = 0;
            }
        }
    }
    if ch == PAD {
        ch = at(p);
        p += 1;
        match state {
            0 | 1 => return -1,
            2 => {
                // one byte of data: another `=` must follow (white space may come first)
                while ch != 0 && is_space(ch) {
                    ch = at(p);
                    p += 1;
                }
                if ch != PAD {
                    return -1;
                }
                ch = at(p);
                p += 1;
                // fall through to the single trailing `=` case
                while ch != 0 {
                    if !is_space(ch) {
                        return -1;
                    }
                    ch = at(p);
                    p += 1;
                }
                // states 2 and 3 checked `tarindex + 1 < targsize` when they wrote, so the index is inside `t`
                if target.as_deref().is_some_and(|t| t[tarindex] != 0) {
                    return -1;
                }
            }
            _ => {
                while ch != 0 {
                    if !is_space(ch) {
                        return -1;
                    }
                    ch = at(p);
                    p += 1;
                }
                if target.as_deref().is_some_and(|t| t[tarindex] != 0) {
                    return -1;
                }
            }
        }
    } else if state != 0 {
        // ended on the end of the text with a partial byte
        return -1;
    }
    tarindex as c_int
}

/// Decode the NUL-terminated base-64 text `src` into `target`. Returns the number of bytes, or -1 on bad input or when
/// `targsize` is too small. With a NULL `target` only the length is computed.
///
/// # Safety
/// `src` is a C string; `target` is NULL or writable for `targsize` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __b64_pton(src: *const c_char, target: *mut c_uchar, targsize: usize) -> c_int {
    // SAFETY: the caller's contract: `src` is a C string.
    let src = unsafe { ffi::cstr_bytes(src) };
    let target = if target.is_null() {
        None
    } else {
        // SAFETY: the caller's contract: a non-NULL `target` is writable for `targsize` bytes.
        Some(unsafe { ffi::bytes_mut(target, targsize) })
    };
    pton(src, target)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    unsafe extern "C" {
        fn __b64_ntop(src: *const c_uchar, srclength: usize, target: *mut c_char, targsize: usize) -> c_int;
        fn __b64_pton(src: *const c_char, target: *mut c_uchar, targsize: usize) -> c_int;
    }

    // the host glibc's functions are the oracle
    #[test]
    fn same_as_host_glibc() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..20000 {
            let n = (rnd() % 40) as usize;
            let data: Vec<u8> = (0..n).map(|_| rnd() as u8).collect();
            let cap = (rnd() % 70) as usize;
            let (mut a, mut b) = (vec![0x55 as c_char; 80], vec![0x55 as c_char; 80]);
            let ra = unsafe { super::__b64_ntop(data.as_ptr(), n, a.as_mut_ptr(), cap) };
            let rb = unsafe { __b64_ntop(data.as_ptr(), n, b.as_mut_ptr(), cap) };
            assert_eq!(ra, rb, "ntop result round {round}");
            if ra >= 0 {
                assert_eq!(a[..ra as usize + 1], b[..ra as usize + 1]);
            }
            // decode: valid text, and text with random damage
            let mut text: Vec<u8> = Vec::new();
            if ra >= 0 {
                text = a[..ra as usize].iter().map(|&c| c as u8).collect();
            }
            if rnd() % 3 == 0 && !text.is_empty() {
                let k = (rnd() as usize) % text.len();
                text[k] = b" =+/\nA9!\0z"[(rnd() % 10) as usize];
            }
            let mut z = text.clone();
            z.push(0);
            let tcap = (rnd() % 50) as usize;
            let (mut da, mut db) = (vec![0xaau8; 60], vec![0xaau8; 60]);
            let pa = unsafe { super::__b64_pton(z.as_ptr() as *const c_char, da.as_mut_ptr(), tcap) };
            let pb = unsafe { __b64_pton(z.as_ptr() as *const c_char, db.as_mut_ptr(), tcap) };
            assert_eq!(pa, pb, "pton result round {round} text {:?}", String::from_utf8_lossy(&text));
            if pa >= 0 {
                assert_eq!(da[..pa as usize], db[..pa as usize]);
            }
            let ca = unsafe { super::__b64_pton(z.as_ptr() as *const c_char, core::ptr::null_mut(), 0) };
            let cb = unsafe { __b64_pton(z.as_ptr() as *const c_char, core::ptr::null_mut(), 0) };
            assert_eq!(ca, cb, "pton count round {round}");
        }
    }
}
