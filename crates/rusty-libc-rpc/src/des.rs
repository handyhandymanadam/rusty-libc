use crate::vars::*;
use core::ffi::{c_char, c_int, c_uint};

pub const DES_MAXDATA: c_uint = 8192;
pub const DES_DIRMASK: c_uint = 1;
pub const DES_ENCRYPT: c_uint = 0;
pub const DES_DECRYPT: c_uint = 1;
pub const DES_DEVMASK: c_uint = 2;
pub const DES_HW: c_uint = 0;
pub const DES_SW: c_uint = 2;
pub const DESERR_NONE: c_int = 0;
pub const DESERR_NOHWDEVICE: c_int = 1;
pub const DESERR_HWERROR: c_int = 2;
pub const DESERR_BADPARAM: c_int = 3;

pub fn des_failed(err: c_int) -> bool {
    err > DESERR_NOHWDEVICE
}

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45,
    37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42,
    10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P: [u8; 32] = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 28, 20, 12, 4,
];
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const SBOX: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5,
        11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2,
        11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7,
        4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8,
        9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13,
        6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10,
        11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7,
        9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13,
        15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

fn permute(input: u64, table: &[u8], n_in: u32) -> u64 {
    let mut out = 0u64;
    for &t in table {
        out = (out << 1) | ((input >> (n_in - t as u32)) & 1);
    }
    out
}

pub fn key_schedule(key: &[u8; 8]) -> [u64; 16] {
    let k = u64::from_be_bytes(*key);
    let cd = permute(k, &PC1, 64);
    let mut c = (cd >> 28) as u32 & 0x0fff_ffff;
    let mut d = cd as u32 & 0x0fff_ffff;
    let mut out = [0u64; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let s = SHIFTS[i] as u32;
        c = ((c << s) | (c >> (28 - s))) & 0x0fff_ffff;
        d = ((d << s) | (d >> (28 - s))) & 0x0fff_ffff;
        let cd = ((c as u64) << 28) | d as u64;
        *o = permute(cd, &PC2, 56);
    }
    out
}

fn feistel(r: u32, k: u64) -> u32 {
    let x = permute(r as u64, &E, 32) ^ k;
    let mut out = 0u32;
    for i in 0..8 {
        let six = ((x >> (42 - 6 * i)) & 0x3f) as usize;
        let row = ((six & 0x20) >> 4) | (six & 1);
        let col = (six >> 1) & 0xf;
        out = (out << 4) | SBOX[i][row * 16 + col] as u32;
    }
    permute(out as u64, &P, 32) as u32
}

pub fn des_block_op(ks: &[u64; 16], block: u64, decrypt: bool) -> u64 {
    let ip = permute(block, &IP, 64);
    let mut l = (ip >> 32) as u32;
    let mut r = ip as u32;
    for i in 0..16 {
        let k = if decrypt { ks[15 - i] } else { ks[i] };
        let t = r;
        r = l ^ feistel(r, k);
        l = t;
    }
    permute(((r as u64) << 32) | l as u64, &FP, 64)
}

pub fn crypt_in_place(key: &[u8; 8], buf: &mut [u8], decrypt: bool, ivec: Option<&mut [u8; 8]>) {
    let ks = key_schedule(key);
    match ivec {
        None => {
            for ch in buf.chunks_exact_mut(8) {
                let b = u64::from_be_bytes(ch.try_into().unwrap());
                ch.copy_from_slice(&des_block_op(&ks, b, decrypt).to_be_bytes());
            }
        }
        Some(iv) => {
            let mut prev = u64::from_be_bytes(*iv);
            if decrypt && buf.len() < 8 {
                prev = 0;
            }
            for ch in buf.chunks_exact_mut(8) {
                let b = u64::from_be_bytes(ch.try_into().unwrap());
                if decrypt {
                    let o = des_block_op(&ks, b, true) ^ prev;
                    prev = b;
                    ch.copy_from_slice(&o.to_be_bytes());
                } else {
                    let o = des_block_op(&ks, b ^ prev, false);
                    prev = o;
                    ch.copy_from_slice(&o.to_be_bytes());
                }
            }
            *iv = prev.to_be_bytes();
        }
    }
}

unsafe fn common_crypt(key: *const c_char, buf: *mut c_char, len: c_uint, mode: c_uint, ivec: Option<&mut [u8; 8]>) -> c_int {
    if len % 8 != 0 || len > DES_MAXDATA {
        return DESERR_BADPARAM;
    }
    let decrypt = mode & DES_DIRMASK != DES_ENCRYPT;
    let desdev = mode & DES_DEVMASK;
    let mut k = [0u8; 8];
    core::ptr::copy_nonoverlapping(key as *const u8, k.as_mut_ptr(), 8);
    let b = core::slice::from_raw_parts_mut(buf as *mut u8, len as usize);
    crypt_in_place(&k, b, decrypt, ivec);
    if desdev == DES_SW { DESERR_NONE } else { DESERR_NOHWDEVICE }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cbc_crypt(key: *mut c_char, buf: *mut c_char, len: c_uint, mode: c_uint, ivec: *mut c_char) -> c_int {
    let mut iv = [0u8; 8];
    core::ptr::copy_nonoverlapping(ivec as *const u8, iv.as_mut_ptr(), 8);
    let err = common_crypt(key, buf, len, mode, Some(&mut iv));
    core::ptr::copy_nonoverlapping(iv.as_ptr(), ivec as *mut u8, 8);
    err
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ecb_crypt(key: *mut c_char, buf: *mut c_char, len: c_uint, mode: c_uint) -> c_int {
    common_crypt(key, buf, len, mode, None)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn des_setparity(p: *mut c_char) {
    for i in 0..8 {
        let b = (*p.add(i) as u8) & 0x7e;
        *p.add(i) = (if b.count_ones() % 2 == 0 { b | 1 } else { b }) as c_char;
    }
}

pub unsafe fn passwd2des_internal(mut pw: *const c_char, key: *mut c_char) {
    core::ptr::write_bytes(key, 0, 8);
    let mut i = 0;
    while *pw != 0 && i < 8 {
        *key.add(i) = (*key.add(i) as c_int ^ ((*pw as c_int) << 1)) as c_char;
        pw = pw.add(1);
        i += 1;
    }
    des_setparity(key);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn passwd2des(pw: *mut c_char, key: *mut c_char) {
    passwd2des_internal(pw, key)
}

fn hexval(c: c_char) -> c_int {
    let c = c as c_int;
    if (b'0' as c_int..=b'9' as c_int).contains(&c) {
        c - b'0' as c_int
    } else {
        let upp = if (b'a' as c_int..=b'z' as c_int).contains(&c) { c - 32 } else { c };
        if (b'A' as c_int..=b'Z' as c_int).contains(&upp) { upp - b'A' as c_int + 10 } else { -1 }
    }
}

unsafe fn hex2bin(len: usize, hexnum: *const c_char, binnum: *mut c_char) {
    for i in 0..len {
        *binnum.add(i) = (16 * hexval(*hexnum.add(2 * i)) + hexval(*hexnum.add(2 * i + 1))) as c_char;
    }
}

unsafe fn bin2hex(len: usize, binnum: *const u8, hexnum: *mut c_char) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..len {
        let val = *binnum.add(i) as usize;
        *hexnum.add(i * 2) = HEX[val >> 4] as c_char;
        *hexnum.add(i * 2 + 1) = HEX[val & 0xf] as c_char;
    }
    *hexnum.add(len * 2) = 0;
}

unsafe fn xcrypt(secret: *mut c_char, passwd: *mut c_char, mode: c_uint) -> c_int {
    let len = strlen(secret) / 2;
    let buf = mem_alloc(len) as *mut c_char;
    hex2bin(len, secret, buf);
    let mut key = [0 as c_char; 8];
    passwd2des_internal(passwd, key.as_mut_ptr());
    let mut ivec = [0 as c_char; 8];
    let err = cbc_crypt(key.as_mut_ptr(), buf, len as c_uint, mode | DES_HW, ivec.as_mut_ptr());
    if des_failed(err) {
        mem_free(buf.cast());
        return 0;
    }
    bin2hex(len, buf as *const u8, secret);
    mem_free(buf.cast());
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xencrypt(secret: *mut c_char, passwd: *mut c_char) -> c_int {
    xcrypt(secret, passwd, DES_ENCRYPT)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdecrypt(secret: *mut c_char, passwd: *mut c_char) -> c_int {
    xcrypt(secret, passwd, DES_DECRYPT)
}
