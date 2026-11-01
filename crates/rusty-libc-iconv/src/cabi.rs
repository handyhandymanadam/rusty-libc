//! The C functions: iconv_open, iconv, iconv_close.
//!
//! Thin unsafe shell (BRIEF-UNSAFE U2): each C function turns its raw arguments into references and slices once (core's
//! `ffi` helpers), the work is done by safe code on [`Converter`] ([`open`], `convert_raw`, `flush_raw`), and the results go back through the
//! in/out pointers and errno. What stays unsafe here: reading the caller's pointers, `malloc`/`free` of the handle.
use crate::conv::Converter;
use crate::gconv_abi::{ENCOUNTERED_ILLEGAL_INPUT as GCONV_ENCOUNTERED_ILLEGAL_INPUT, StepData};
#[cfg(any(feature = "shared", test))]
use crate::gconv_abi::InfoHead;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::errno;
use rusty_libc_core::ffi::{bytes, bytes_mut, cstr_bytes, out};

/// `iconv_t`: a pointer to a heap-allocated [`Handle`]; `(iconv_t)-1` means failure.
#[allow(non_camel_case_types)]
pub type iconv_t = *mut c_void;

/// What an `iconv_t` points to. It begins like glibc's `struct __gconv_info` (`size_t __nsteps; struct __gconv_step *__steps;
/// struct __gconv_step_data __data[]`), because glibc's own `iconv` program (which links against the shared library) reads
/// `cd->__nsteps` and `cd->__data[i].__flags` after the conversion to tell whether `-c` skipped illegal input. One step is
/// reported; `steps` is NULL (nothing outside glibc can use a step without its private functions).
#[repr(C)]
struct Handle {
    nsteps: usize,
    steps: *mut c_void,
    data: [StepData; 1],
    conv: Converter,
}

/// ENOMEM (core's errno module does not name it).
const ENOMEM: i32 = 12;

/// The failure value of `iconv_open` and `iconv`: `(iconv_t)-1`, `(size_t)-1`.
const FAILED: usize = usize::MAX;

/// `iconv_open` on Rust byte strings (the names without their NUL): a new handle, or `(iconv_t)-1` with errno EINVAL (no
/// such conversion) or ENOMEM. `__gconv_open` uses it too.
pub(crate) fn open(to: &[u8], from: &[u8]) -> iconv_t {
    // names from `GCONV_PATH` take priority over the built-in charsets
    #[cfg(any(feature = "shared", test))]
    if crate::gconv_conf::user_modules()
        && let Some(cd) = open_plugin(to, from, false)
    {
        return cd;
    }
    let conv = match Converter::open(to, from) {
        Ok(conv) => conv,
        Err(_) => {
            // a charset that is not built in may come from a module of the system directory, or be an alias of a built-in
            // one that a `GCONV_PATH` file defines
            #[cfg(any(feature = "shared", test))]
            if let Some(cd) = open_plugin(to, from, true) {
                return cd;
            }
            #[cfg(any(feature = "shared", test))]
            if let Some(conv) = open_alias(to, from) {
                return finish_open(conv);
            }
            errno::set(errno::EINVAL);
            return FAILED as iconv_t;
        }
    };
    finish_open(conv)
}

/// The handle of a plain (built-in) conversion.
fn finish_open(conv: Converter) -> iconv_t {
    // SAFETY: malloc may be called with any size; the result is checked for NULL below.
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
    // SAFETY: `p` is a fresh, non-NULL allocation of `size_of::<Handle>()` bytes, aligned for `Handle` (malloc aligns to 16,
    // `Handle` needs 8); nothing else refers to it yet, and writing does not read or drop the uninitialised memory.
    unsafe { p.write(h) };
    p.cast()
}

/// A built-in conversion between names that a `GCONV_PATH` file made aliases of built-in charsets.
#[cfg(any(feature = "shared", test))]
fn open_alias(to: &[u8], from: &[u8]) -> Option<Converter> {
    let (pt, pf) = (crate::names::parse(to)?, crate::names::parse(from)?);
    let (alias_to, alias_from) = crate::gconv_conf::expand_aliases(pt.key(), pf.key())?;
    // the target name with the error handling the caller asked for, as `iconv_open` reads `NAME//TRANSLIT,IGNORE`
    let alias_to = crate::names::parse(alias_to.as_bytes())?;
    let mut name = [0u8; 320];
    let mut n = alias_to.key().len();
    name[..n].copy_from_slice(alias_to.key());
    for (on, word) in [(pt.translit, &b"TRANSLIT"[..]), (pt.ignore, &b"IGNORE"[..])] {
        if on {
            if n > alias_to.key().len() {
                name[n] = b',';
                n += 1;
            }
            name[n..n + word.len()].copy_from_slice(word);
            n += word.len();
        }
    }
    Converter::open(&name[..n], alias_from.as_bytes()).ok()
}

/// A conversion that goes through plug-in modules, if the module files give one for these names: the descriptor, or
/// `(iconv_t)-1` with errno set as glibc's `iconv_open` would; `None` when no module is involved.
#[cfg(any(feature = "shared", test))]
fn open_plugin(to: &[u8], from: &[u8], system: bool) -> Option<iconv_t> {
    use crate::gconv_chain::{self, Failure};
    use crate::gconv_conf::{self, Lookup};
    let (pt, pf) = (crate::names::parse(to)?, crate::names::parse(from)?);
    // (an empty name means the locale's charset, which only the built-in code resolves)
    if pt.key() == b"//" || pf.key() == b"//" {
        return None;
    }
    let Lookup::Path(path) = gconv_conf::lookup(pt.key(), pf.key(), system) else { return None };
    Some(match gconv_chain::open(&path, pt.translit, pt.ignore) {
        Ok(cd) => cd,
        Err(failure) => {
            if let Failure::Errno(e) = failure {
                errno::set(e);
            }
            FAILED as iconv_t
        }
    })
}

impl Handle {
    /// After a call: record "illegal input seen" in the step flags for glibc's `iconv` program.
    #[inline(always)]
    fn note_illegal(&mut self) {
        if self.conv.illegal_seen() {
            self.data[0].flags |= GCONV_ENCOUNTERED_ILLEGAL_INPUT;
        }
    }
}

/// `iconv_t iconv_open(const char *tocode, const char *fromcode)`.
///
/// # Safety
/// Both names are NUL-terminated strings (NULL faults, as in glibc).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> iconv_t {
    // SAFETY: `tocode` is a NUL-terminated string (the caller's contract), only read during this call.
    let to = unsafe { cstr_bytes(tocode) };
    // SAFETY: as above, for `fromcode`.
    let from = unsafe { cstr_bytes(fromcode) };
    open(to, from)
}

/// `int iconv_close(iconv_t cd)`: frees the handle; `(iconv_t)-1` and NULL are ignored. Always 0.
///
/// # Safety
/// `cd` came from `iconv_open` (or is `(iconv_t)-1` or NULL) and is not used again.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv_close(cd: iconv_t) -> c_int {
    if cd as usize != FAILED && !cd.is_null() {
        // a descriptor of plug-in modules has its step list set
        #[cfg(any(feature = "shared", test))]
        {
            // SAFETY: `cd` is a live descriptor of this library (the caller's contract); both kinds begin with the step count
            // and the step list.
            let head = unsafe { out(cd.cast::<InfoHead>()) };
            if head.is_some_and(|h| !h.steps.is_null()) {
                // SAFETY: a descriptor with a step list came from `gconv_chain::open` and is not used again.
                unsafe { crate::gconv_chain::close(cd) };
                return 0;
            }
        }
        // SAFETY: `cd` is a live allocation from `open`'s malloc (the caller's contract) and is not used after this.
        // `Converter` has no drop glue, so freeing without dropping leaks nothing.
        unsafe { rusty_libc_malloc::free(cd) };
    }
    0
}

/// `size_t iconv(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)`.
///
/// # Safety
/// `cd` came from `iconv_open` (or is `(iconv_t)-1` or NULL: EBADF). `inbuf` is NULL or points to a pointer that is NULL or
/// points to `*inbytesleft` readable bytes; likewise `outbuf`, `*outbuf` and `*outbytesleft` for writable bytes. The count
/// pointers are dereferenced only when their buffer is given. The buffers do not overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iconv(
    cd: iconv_t,
    inbuf: *mut *mut c_char,
    inbytesleft: *mut usize,
    outbuf: *mut *mut c_char,
    outbytesleft: *mut usize,
) -> usize {
    // a descriptor of plug-in modules has its step list set
    #[cfg(any(feature = "shared", test))]
    if cd as usize != FAILED {
        // SAFETY: NULL or a live descriptor of this library (the caller's contract); both kinds begin with the step count and
        // the step list.
        let head = unsafe { out(cd.cast::<InfoHead>()) };
        if head.is_some_and(|h| !h.steps.is_null()) {
            // SAFETY: a descriptor with a step list came from `gconv_chain::open`; the pointers are the caller's.
            return unsafe { crate::gconv_chain::convert(cd, inbuf, inbytesleft, outbuf, outbytesleft) };
        }
    }
    // `(iconv_t)-1` and NULL: EBADF
    let h = if cd as usize == FAILED {
        None
    } else {
        // SAFETY: not `(iconv_t)-1`, so NULL or a live handle from `open` (the caller's contract) that no other thread uses
        // during the call (iconv descriptors are not shared during a call, as in glibc); `out` maps NULL to `None`.
        unsafe { out(cd.cast::<Handle>()) }
    };
    let Some(h) = h else {
        errno::set(errno::EBADF);
        return FAILED;
    };

    // SAFETY: `inbuf` is NULL or points to the caller's input pointer, which nothing else touches during the call.
    let inp = unsafe { out(inbuf) }.filter(|p| !p.is_null());
    // SAFETY: as above, for `outbuf`.
    let outp = unsafe { out(outbuf) }.filter(|p| !p.is_null());
    // The output room, read only when there is an output buffer (the flush form may pass NULL counts).
    let (outleft, room): (Option<&mut usize>, &mut [u8]) = match &outp {
        Some(p) => {
            // SAFETY: with an output buffer, `outbytesleft` points to its room (the caller's contract; NULL faults as in glibc).
            let n = unsafe { &mut *outbytesleft };
            // SAFETY: `*outbuf` points to `*outbytesleft` writable bytes that nothing else accesses during the call and that do
            // not overlap the input (the caller's contract).
            let room = unsafe { bytes_mut(p.cast::<u8>(), *n) };
            (Some(n), room)
        }
        None => (None, &mut []),
    };
    let mut op = 0usize;
    let r = match inp {
        // flush / reset (`inbuf` or `*inbuf` NULL)
        None => {
            if outp.is_some() { h.conv.flush_raw(Some((room, &mut op))) } else { h.conv.flush_raw(None) }
        }
        Some(p) => {
            // SAFETY: with an input buffer, `inbytesleft` points to its length (the caller's contract; NULL faults as in glibc).
            let n = unsafe { &mut *inbytesleft };
            // SAFETY: `*inbuf` points to `*inbytesleft` readable bytes that do not change during the call (the caller's contract).
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

#[cfg(test)]
mod tests {
    //! The C entry points (their Rust items: `export` is off in tests) against the host's glibc, call by call: return value,
    //! errno, how far the four in/out arguments moved, output bytes.
    use super::*;
    use std::ffi::CString;

    mod host {
        use core::ffi::{c_char, c_int, c_void};
        unsafe extern "C" {
            pub fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
            pub fn iconv(cd: *mut c_void, ib: *mut *mut c_char, il: *mut usize, ob: *mut *mut c_char, ol: *mut usize) -> usize;
            pub fn iconv_close(cd: *mut c_void) -> c_int;
        }
    }

    type IconvFn = unsafe extern "C" fn(iconv_t, *mut *mut c_char, *mut usize, *mut *mut c_char, *mut usize) -> usize;

    /// What one call did: (return value, errno or 0, input used, output written, output bytes).
    type Outcome = (usize, i32, usize, usize, Vec<u8>);

    /// One call; `input`/`out` None pass NULL for `inbuf`/`outbuf` (and NULL counts).
    fn call(f: IconvFn, cd: iconv_t, input: Option<&[u8]>, out: Option<usize>) -> Outcome {
        let mut inb = input.unwrap_or(&[]).to_vec();
        let mut outb = vec![0u8; out.unwrap_or(0) + 1];
        let (mut ip, mut il) = (inb.as_mut_ptr().cast::<c_char>(), input.map_or(0, |i| i.len()));
        let (mut op, mut ol) = (outb.as_mut_ptr().cast::<c_char>(), out.unwrap_or(0));
        let (ib0, ob0) = (ip, op);
        errno::set(0);
        let (pi, pil) = if input.is_some() { (&raw mut ip, &raw mut il) } else { (null_mut(), null_mut()) };
        let (po, pol) = if out.is_some() { (&raw mut op, &raw mut ol) } else { (null_mut(), null_mut()) };
        // SAFETY: the pointers describe `inb` and `outb`, which outlive the call; `cd` is open (or -1 on purpose).
        let r = unsafe { f(cd, pi, pil, po, pol) };
        let e = if r == usize::MAX { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
        let used = ip as usize - ib0 as usize;
        let wrote = op as usize - ob0 as usize;
        assert_eq!(input.map_or(0, |i| i.len()) - il, used, "inbytesleft moves with inbuf");
        assert_eq!(out.unwrap_or(0) - ol, wrote, "outbytesleft moves with outbuf");
        outb.truncate(wrote);
        (r, e, used, wrote, outb)
    }

    fn ours_iconv(cd: iconv_t, ib: *mut *mut c_char, il: *mut usize, ob: *mut *mut c_char, ol: *mut usize) -> usize {
        // SAFETY: forwarded from `call`.
        let r = unsafe { iconv(cd, ib, il, ob, ol) };
        // our errno lives in core's thread-local; copy it to the host's for `call`
        if r == usize::MAX {
            let e = errno::get();
            set_host_errno(e);
        }
        r
    }

    fn set_host_errno(e: i32) {
        unsafe extern "C" {
            fn __errno_location() -> *mut c_int;
        }
        // SAFETY: __errno_location has no preconditions.
        let p = unsafe { __errno_location() };
        // SAFETY: the calling thread's errno, valid and aligned.
        unsafe { *p = e };
    }

    unsafe extern "C" fn ours_c(cd: iconv_t, ib: *mut *mut c_char, il: *mut usize, ob: *mut *mut c_char, ol: *mut usize) -> usize {
        ours_iconv(cd, ib, il, ob, ol)
    }

    fn pair(to: &str, from: &str) -> (iconv_t, iconv_t) {
        let (t, f) = (CString::new(to).unwrap(), CString::new(from).unwrap());
        // SAFETY: NUL-terminated names that outlive the calls.
        let a = unsafe { iconv_open(t.as_ptr(), f.as_ptr()) };
        // SAFETY: as above.
        let b = unsafe { host::iconv_open(t.as_ptr(), f.as_ptr()) };
        assert_ne!(a as usize, FAILED, "{to} <- {from}");
        assert_ne!(b as usize, FAILED);
        (a, b)
    }

    fn close(a: iconv_t, b: iconv_t) {
        // SAFETY: open descriptors, closed once.
        assert_eq!(unsafe { iconv_close(a) }, 0);
        // SAFETY: as above.
        unsafe { host::iconv_close(b) };
    }

    #[test]
    fn c_entry_points_match_glibc() {
        type Call<'a> = (Option<&'a [u8]>, Option<usize>);
        let cases: &[(&str, &str, &[Call])] = &[
            ("ISO-8859-1", "UTF-8", &[(Some(b"h\xc3\xa9llo"), Some(64)), (Some(b"ab\xc3"), Some(64)), (Some(b"\xe2\x82\xac"), Some(64))]),
            ("UTF-16", "UTF-8", &[(Some(b"abc"), Some(3)), (Some(b"abc"), Some(64)), (None, Some(8))]),
            ("ISO-2022-JP", "UTF-8", &[(Some("a\u{3042}".as_bytes()), Some(64)), (None, Some(2)), (None, Some(64)), (None, None)]),
            ("ASCII//TRANSLIT", "UTF-8", &[(Some("\u{e9}t\u{e9}".as_bytes()), Some(64))]),
            ("ASCII//IGNORE", "UTF-8", &[(Some("a\u{e9}b".as_bytes()), Some(64)), (Some(b"c"), Some(64))]),
            ("UTF-8", "UTF-8", &[(Some(b"\xff"), Some(64)), (Some(b""), Some(0)), (Some(b"abc"), Some(0))]),
        ];
        for &(to, from, steps) in cases {
            let (a, b) = pair(to, from);
            for (i, &(input, out)) in steps.iter().enumerate() {
                let ours = call(ours_c, a, input, out);
                let glibc = call(host::iconv, b, input, out);
                assert_eq!(ours, glibc, "{to} <- {from}, step {i}");
            }
            close(a, b);
        }
        // input but no output buffer: glibc dereferences NULL there; ours reports a full output
        let (a, b) = pair("UTF-16LE", "UTF-8");
        assert_eq!(call(ours_c, a, Some(b"x"), None), (FAILED, 7, 0, 0, vec![]));
        close(a, b);
        // EBADF for (iconv_t)-1
        let ours = call(ours_c, FAILED as iconv_t, Some(b"a"), Some(4));
        let glibc = call(host::iconv, FAILED as iconv_t, Some(b"a"), Some(4));
        assert_eq!(ours, glibc);
        // unknown charset: EINVAL
        let (t, f) = (CString::new("NO-SUCH-CHARSET").unwrap(), CString::new("UTF-8").unwrap());
        errno::set(0);
        // SAFETY: NUL-terminated names that outlive the call.
        assert_eq!(unsafe { iconv_open(t.as_ptr(), f.as_ptr()) } as usize, FAILED);
        assert_eq!(errno::get(), errno::EINVAL);
    }

    #[test]
    fn illegal_input_flag_for_glibc_iconv_program() {
        let (t, f) = (CString::new("ASCII//IGNORE").unwrap(), CString::new("UTF-8").unwrap());
        // SAFETY: NUL-terminated names that outlive the call.
        let cd = unsafe { iconv_open(t.as_ptr(), f.as_ptr()) };
        let _ = call(ours_c, cd, Some(b"a"), Some(8));
        // SAFETY: a live handle of this test, not used by anyone else.
        let h = unsafe { out(cd.cast::<Handle>()) }.unwrap();
        assert_eq!(h.data[0].flags & GCONV_ENCOUNTERED_ILLEGAL_INPUT, 0);
        assert_eq!(h.nsteps, 1);
        let _ = call(ours_c, cd, Some("\u{e9}".as_bytes()), Some(8));
        // SAFETY: as above.
        let h = unsafe { out(cd.cast::<Handle>()) }.unwrap();
        assert_ne!(h.data[0].flags & GCONV_ENCOUNTERED_ILLEGAL_INPUT, 0);
        // SAFETY: open, closed once.
        unsafe { iconv_close(cd) };
    }
}
