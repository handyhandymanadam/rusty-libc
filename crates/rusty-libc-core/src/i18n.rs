#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, c_char};
use core::sync::atomic::{AtomicUsize, Ordering};

pub type TranslateFn = unsafe fn(domain: *const c_char, msgid: *const c_char, loc: usize) -> *const c_char;
pub type FormatFn = unsafe fn(fmt: *const c_char, args: &[u64], out: &mut dyn FnMut(&[u8]));

static TRANSLATE: AtomicUsize = AtomicUsize::new(0);
static FORMAT: AtomicUsize = AtomicUsize::new(0);

pub const LIBC_DOMAIN: &CStr = c"libc";

pub fn install(translate: TranslateFn, format: FormatFn) {
    FORMAT.store(format as usize, Ordering::Release);
    TRANSLATE.store(translate as usize, Ordering::Release);
}

#[inline(always)]
pub fn active() -> bool {
    TRANSLATE.load(Ordering::Relaxed) != 0
}

#[inline(always)]
fn hook() -> Option<TranslateFn> {
    let f = TRANSLATE.load(Ordering::Acquire);
    if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, TranslateFn>(f) }) }
}

#[cold]
#[inline(never)]
fn call(f: TranslateFn, domain: *const c_char, msgid: *const c_char, loc: usize) -> *const c_char {
    unsafe { f(domain, msgid, loc) }
}

#[inline]
pub fn tr(msgid: &'static CStr) -> &'static CStr {
    match hook() {
        None => msgid,
        Some(f) => unsafe { CStr::from_ptr(call(f, LIBC_DOMAIN.as_ptr(), msgid.as_ptr(), 0)) },
    }
}

#[inline]
pub unsafe fn tr_ptr(msgid: *const c_char) -> *const c_char {
    match hook() {
        None => msgid,
        Some(f) => call(f, LIBC_DOMAIN.as_ptr(), msgid, 0),
    }
}

#[inline]
pub unsafe fn tr_l(msgid: &'static CStr, loc: usize) -> &'static CStr {
    match hook() {
        None => msgid,
        Some(f) => unsafe { CStr::from_ptr(call(f, LIBC_DOMAIN.as_ptr(), msgid.as_ptr(), loc)) },
    }
}

#[inline]
pub unsafe fn dtr(domain: *const c_char, msgid: *const c_char) -> *const c_char {
    if msgid.is_null() {
        return msgid;
    }
    match hook() {
        None => msgid,
        Some(f) => call(f, domain, msgid, 0),
    }
}

#[inline]
pub fn tr_format(msgid: &'static CStr, args: &[u64], out: &mut dyn FnMut(&[u8])) -> bool {
    let Some(f) = hook() else { return false };
    let t = call(f, LIBC_DOMAIN.as_ptr(), msgid.as_ptr(), 0);
    if core::ptr::eq(t, msgid.as_ptr()) {
        return false;
    }
    unsafe { format(t, args, out) };
    true
}

#[cold]
pub unsafe fn format(fmt: *const c_char, args: &[u64], out: &mut dyn FnMut(&[u8])) {
    let f = FORMAT.load(Ordering::Acquire);
    if f == 0 {
        return;
    }
    let f = unsafe { core::mem::transmute::<usize, FormatFn>(f) };
    unsafe { f(fmt, args, out) }
}

pub fn libc_message_pieces<'a>(fmt: &'a [u8], args: &[&'a [u8]], piece: &mut dyn FnMut(&'a [u8])) {
    let mut i = 0;
    let mut start = 0;
    let mut next_arg = 0;
    while i < fmt.len() {
        if fmt[i] == b'%' && fmt.get(i + 1) == Some(&b's') {
            if i > start {
                piece(&fmt[start..i]);
            }
            if let Some(a) = args.get(next_arg) {
                piece(a);
            }
            next_arg += 1;
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < fmt.len() {
        piece(&fmt[start..]);
    }
}
