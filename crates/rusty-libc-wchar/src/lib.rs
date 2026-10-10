#![no_std]
#![no_builtins]
#![allow(clippy::missing_safety_doc)]

mod tables;
mod wvec;
pub mod wstring;
pub mod mbyte;
pub mod wctype;
pub mod wtime;
pub mod wconv;

use core::sync::atomic::{AtomicU8, Ordering};

#[allow(non_camel_case_types)]
pub type wchar_t = i32;
#[allow(non_camel_case_types)]
pub type wint_t = u32;
pub const WEOF: wint_t = 0xffff_ffff;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct mbstate_t {
    pub count: i32,
    pub value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    C,
    Utf8,
    Other,
}

static CHARSET: AtomicU8 = AtomicU8::new(0);

pub fn set_charset(c: Charset) {
    CHARSET.store(c as u8, Ordering::Relaxed);
}

#[inline]
pub fn charset() -> Charset {
    let t = rusty_libc_core::locale::thread();
    if !t.is_null() {
        let d = unsafe { *t };
        if !d.is_null() {
            let code = unsafe { (*d).flags } >> rusty_libc_core::locale::F_CHARSET_SHIFT & 0xff;
            return code_charset(code);
        }
    }
    code_charset(CHARSET.load(Ordering::Relaxed) as u32)
}

#[inline]
fn code_charset(code: u32) -> Charset {
    match code {
        0 => Charset::C,
        1 => Charset::Utf8,
        _ => Charset::Other,
    }
}

