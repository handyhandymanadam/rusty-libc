#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use core::ffi::{c_char, c_int, c_uchar};
use rusty_libc_core::ffi;

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __b64_ntop(src: *const c_uchar, srclength: usize, target: *mut c_char, targsize: usize) -> c_int {
    let src = unsafe { ffi::bytes(src, srclength) };
    let target = unsafe { ffi::bytes_mut(target.cast::<u8>(), targsize) };
    ntop(src, target)
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

pub fn pton(src: &[u8], mut target: Option<&mut [u8]>) -> c_int {
    let targsize = target.as_ref().map_or(0, |t| t.len());
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
                while ch != 0 && is_space(ch) {
                    ch = at(p);
                    p += 1;
                }
                if ch != PAD {
                    return -1;
                }
                ch = at(p);
                p += 1;
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
        return -1;
    }
    tarindex as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __b64_pton(src: *const c_char, target: *mut c_uchar, targsize: usize) -> c_int {
    let src = unsafe { ffi::cstr_bytes(src) };
    let target = if target.is_null() {
        None
    } else {
        Some(unsafe { ffi::bytes_mut(target, targsize) })
    };
    pton(src, target)
}

