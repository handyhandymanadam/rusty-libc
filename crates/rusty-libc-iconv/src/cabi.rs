use crate::conv::Converter;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::errno;
use rusty_libc_core::ffi::{bytes, bytes_mut, cstr_bytes, out};

#[allow(non_camel_case_types)]
pub type iconv_t = *mut c_void;

#[repr(C)]
struct StepData {
    outbuf: *mut u8,
    outbufend: *mut u8,
    flags: c_int,
    invocation_counter: c_int,
    internal_use: c_int,
    statep: *mut c_void,
    state: [c_int; 2],
}

const GCONV_ENCOUNTERED_ILLEGAL_INPUT: c_int = 1 << 30;

#[repr(C)]
struct Handle {
    nsteps: usize,
    steps: *mut c_void,
    data: [StepData; 1],
    conv: Converter,
}

const ENOMEM: i32 = 12;

const FAILED: usize = usize::MAX;

pub(crate) fn open(to: &[u8], from: &[u8]) -> iconv_t {
    let Ok(conv) = Converter::open(to, from) else {
        errno::set(errno::EINVAL);
        return FAILED as iconv_t;
    };
    let p = unsafe { rusty_libc_malloc::malloc(size_of::<Handle>()) }.cast::<Handle>();
    if p.is_null() {
        errno::set(ENOMEM);
        return FAILED as iconv_t;
    }
    let h = Handle {
        nsteps: 1,
        steps: null_mut(),
        data: [StepData { outbuf: null_mut(), outbufend: null_mut(), flags: 0, invocation_counter: 0, internal_use: 0, statep: null_mut(), state: [0; 2] }],
        conv,
    };
    unsafe { p.write(h) };
    p.cast()
}

impl Handle {
    #[inline(always)]
    fn note_illegal(&mut self) {
        if self.conv.illegal_seen() {
            self.data[0].flags |= GCONV_ENCOUNTERED_ILLEGAL_INPUT;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> iconv_t {
    let to = unsafe { cstr_bytes(tocode) };
    let from = unsafe { cstr_bytes(fromcode) };
    open(to, from)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv_close(cd: iconv_t) -> c_int {
    if cd as usize != FAILED && !cd.is_null() {
        unsafe { rusty_libc_malloc::free(cd) };
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv(
    cd: iconv_t,
    inbuf: *mut *mut c_char,
    inbytesleft: *mut usize,
    outbuf: *mut *mut c_char,
    outbytesleft: *mut usize,
) -> usize {
    let h = if cd as usize == FAILED {
        None
    } else {
        unsafe { out(cd.cast::<Handle>()) }
    };
    let Some(h) = h else {
        errno::set(errno::EBADF);
        return FAILED;
    };
    let inp = unsafe { out(inbuf) }.filter(|p| !p.is_null());
    let outp = unsafe { out(outbuf) }.filter(|p| !p.is_null());
    let (outleft, room): (Option<&mut usize>, &mut [u8]) = match &outp {
        Some(p) => {
            let n = unsafe { &mut *outbytesleft };
            let room = unsafe { bytes_mut(p.cast::<u8>(), *n) };
            (Some(n), room)
        }
        None => (None, &mut []),
    };
    let mut op = 0usize;
    let r = match inp {
        None => {
            if outp.is_some() { h.conv.flush_raw(Some((room, &mut op))) } else { h.conv.flush_raw(None) }
        }
        Some(p) => {
            let n = unsafe { &mut *inbytesleft };
            let input = unsafe { bytes(p.cast::<u8>(), *n) };
            let mut ip = 0usize;
            let r = h.conv.convert_raw(input, &mut ip, room, &mut op);
            *p = p.wrapping_add(ip);
            *n -= ip;
            r
        }
    };
    h.note_illegal();
    if let (Some(p), Some(n)) = (outp, outleft) {
        *p = p.wrapping_add(op);
        *n -= op;
    }
    match r {
        Ok(n) => n,
        Err(e) => {
            errno::set(e.errno());
            FAILED
        }
    }
}

