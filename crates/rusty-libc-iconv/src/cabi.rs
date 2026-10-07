use crate::conv::Converter;
use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr::{null_mut, write};

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> iconv_t {
    unsafe {
        let to = CStr::from_ptr(tocode).to_bytes();
        let from = CStr::from_ptr(fromcode).to_bytes();
        let Ok(conv) = Converter::open(to, from) else {
            rusty_libc_core::errno::set(rusty_libc_core::errno::EINVAL);
            return usize::MAX as iconv_t;
        };
        let p = rusty_libc_malloc::malloc(core::mem::size_of::<Handle>()) as *mut Handle;
        if p.is_null() {
            rusty_libc_core::errno::set(12);
            return usize::MAX as iconv_t;
        }
        write(
            p,
            Handle {
                nsteps: 1,
                steps: null_mut(),
                data: [StepData { outbuf: null_mut(), outbufend: null_mut(), flags: 0, invocation_counter: 0, internal_use: 0, statep: null_mut(), state: [0; 2] }],
                conv,
            },
        );
        p as iconv_t
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv_close(cd: iconv_t) -> c_int {
    unsafe {
        if cd as usize != usize::MAX && !cd.is_null() {
            rusty_libc_malloc::free(cd);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv(
    cd: iconv_t,
    inbuf: *mut *mut c_char,
    inbytesleft: *mut usize,
    outbuf: *mut *mut c_char,
    outbytesleft: *mut usize,
) -> usize {
    unsafe {
        let r = iconv_run(cd, inbuf, inbytesleft, outbuf, outbytesleft);
        if cd as usize != usize::MAX && !cd.is_null() {
            let h = cd as *mut Handle;
            if (*h).conv.illegal_seen() {
                (*h).data[0].flags |= GCONV_ENCOUNTERED_ILLEGAL_INPUT;
            }
        }
        r
    }
}

unsafe fn iconv_run(cd: iconv_t, inbuf: *mut *mut c_char, inbytesleft: *mut usize, outbuf: *mut *mut c_char, outbytesleft: *mut usize) -> usize {
    unsafe {
        if cd as usize == usize::MAX || cd.is_null() {
            rusty_libc_core::errno::set(rusty_libc_core::errno::EBADF);
            return usize::MAX;
        }
        let conv = &mut (*(cd as *mut Handle)).conv;
        if inbuf.is_null() || (*inbuf).is_null() {
            let r = if outbuf.is_null() || (*outbuf).is_null() {
                conv.flush_raw(None)
            } else {
                let room = core::slice::from_raw_parts_mut(*outbuf as *mut u8, *outbytesleft);
                let mut op = 0;
                let r = conv.flush_raw(Some((room, &mut op)));
                *outbuf = (*outbuf).add(op);
                *outbytesleft -= op;
                r
            };
            return match r {
                Ok(n) => n,
                Err(e) => {
                    rusty_libc_core::errno::set(e.errno());
                    usize::MAX
                }
            };
        }
        let input = core::slice::from_raw_parts(*inbuf as *const u8, *inbytesleft);
        let (mut ip, mut op) = (0usize, 0usize);
        let room: &mut [u8] = if outbuf.is_null() || (*outbuf).is_null() {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(*outbuf as *mut u8, *outbytesleft)
        };
        let r = conv.convert_raw(input, &mut ip, room, &mut op);
        *inbuf = (*inbuf).add(ip);
        *inbytesleft -= ip;
        if !outbuf.is_null() && !(*outbuf).is_null() {
            *outbuf = (*outbuf).add(op);
            *outbytesleft -= op;
        }
        match r {
            Ok(n) => n,
            Err(e) => {
                rusty_libc_core::errno::set(e.errno());
                usize::MAX
            }
        }
    }
}

#[allow(dead_code)]
fn _unused(_: *mut c_void) -> *mut c_void {
    null_mut()
}
