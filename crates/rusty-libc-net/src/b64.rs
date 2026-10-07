use core::ffi::{c_char, c_int, c_uchar};

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __b64_ntop(src: *const c_uchar, srclength: usize, target: *mut c_char, targsize: usize) -> c_int {
    unsafe {
        let src = core::slice::from_raw_parts(src, srclength);
        let mut datalength = 0usize;
        let mut put = |c: u8| -> bool {
            if datalength >= targsize {
                return false;
            }
            *target.add(datalength) = c as c_char;
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
        *target.add(datalength) = 0;
        datalength as c_int
    }
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __b64_pton(src: *const c_char, target: *mut c_uchar, targsize: usize) -> c_int {
    unsafe {
        let mut p = src as *const u8;
        let mut tarindex = 0usize;
        let mut state = 0u8;
        let mut ch;
        loop {
            ch = *p;
            p = p.add(1);
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
                    if !target.is_null() {
                        if tarindex >= targsize {
                            return -1;
                        }
                        *target.add(tarindex) = pos << 2;
                    }
                    state = 1;
                }
                1 => {
                    if !target.is_null() {
                        if tarindex + 1 >= targsize {
                            return -1;
                        }
                        *target.add(tarindex) |= pos >> 4;
                        *target.add(tarindex + 1) = (pos & 0x0f) << 4;
                    }
                    tarindex += 1;
                    state = 2;
                }
                2 => {
                    if !target.is_null() {
                        if tarindex + 1 >= targsize {
                            return -1;
                        }
                        *target.add(tarindex) |= pos >> 2;
                        *target.add(tarindex + 1) = (pos & 0x03) << 6;
                    }
                    tarindex += 1;
                    state = 3;
                }
                _ => {
                    if !target.is_null() {
                        if tarindex >= targsize {
                            return -1;
                        }
                        *target.add(tarindex) |= pos;
                    }
                    tarindex += 1;
                    state = 0;
                }
            }
        }
        if ch == PAD {
            ch = *p;
            p = p.add(1);
            match state {
                0 | 1 => return -1,
                2 => {
                    while ch != 0 && is_space(ch) {
                        ch = *p;
                        p = p.add(1);
                    }
                    if ch != PAD {
                        return -1;
                    }
                    ch = *p;
                    p = p.add(1);
                    while ch != 0 {
                        if !is_space(ch) {
                            return -1;
                        }
                        ch = *p;
                        p = p.add(1);
                    }
                    if !target.is_null() && *target.add(tarindex) != 0 {
                        return -1;
                    }
                }
                _ => {
                    while ch != 0 {
                        if !is_space(ch) {
                            return -1;
                        }
                        ch = *p;
                        p = p.add(1);
                    }
                    if !target.is_null() && *target.add(tarindex) != 0 {
                        return -1;
                    }
                }
            }
        } else if state != 0 {
            return -1;
        }
        tarindex as c_int
    }
}

