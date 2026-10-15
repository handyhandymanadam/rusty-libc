use crate::file::{self, F_READ, F_WRITE, File as FILE};
use crate::flock::locked;
use core::ffi::c_int;
use core::sync::atomic::Ordering;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fbufsize(f: *mut FILE) -> usize {
    unsafe { file::stream(f) }.bufsize()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fpending(f: *mut FILE) -> usize {
    let s = unsafe { file::stream(f) };
    if s.writing() { s.wpos() } else { 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __flbf(f: *mut FILE) -> c_int {
    (unsafe { file::stream(f) }.flags & file::F_LBF) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadable(f: *mut FILE) -> c_int {
    c_int::from(unsafe { file::stream(f) }.flags & F_READ != 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwritable(f: *mut FILE) -> c_int {
    c_int::from(unsafe { file::stream(f) }.flags & F_WRITE != 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freading(f: *mut FILE) -> c_int {
    let fl = unsafe { file::stream(f) }.flags;
    c_int::from(fl & F_WRITE == 0 || fl & file::F_RDMODE != 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwriting(f: *mut FILE) -> c_int {
    let fl = unsafe { file::stream(f) }.flags;
    c_int::from(fl & F_READ == 0 || fl & file::F_WRMODE != 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fpurge(f: *mut FILE) {
    locked!(f, |s| file::purge(s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _flushlbf() {
    file::flush_line_buffered_pub()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fsetlocking(f: *mut FILE, ty: c_int) -> c_int {
    let nolock = &unsafe { file::shared_of(f) }.nolock;
    let old = if nolock.load(Ordering::Relaxed) { 2 } else { 1 };
    match ty {
        1 => nolock.store(false, Ordering::Relaxed),
        2 => nolock.store(true, Ordering::Relaxed),
        _ => {}
    }
    old
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fseterr(f: *mut FILE) {
    unsafe { file::stream(f) }.flags |= file::F_ERR
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadahead(f: *mut FILE) -> usize {
    let s = unsafe { file::stream(f) };
    if s.writing() {
        return 0;
    }
    let buffered = if s.flags & file::F_RDMODE != 0 { s.rend() - s.rpos() } else { 0 };
    buffered + s.nunget()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadptr(f: *mut FILE, sizep: *mut usize) -> *const core::ffi::c_char {
    let s = unsafe { file::stream(f) };
    if s.flags & (file::F_WRMODE | file::F_RDMODE) != file::F_RDMODE || s.nunget() > 0 || s.rpos() >= s.rend() {
        return core::ptr::null();
    }
    unsafe { *sizep = s.rend() - s.rpos() };
    s.buf.wrapping_add(s.rpos()).cast()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadptrinc(f: *mut FILE, inc: usize) {
    let s = unsafe { file::stream(f) };
    let room = s.rend() - s.rpos();
    s.set_rpos(s.rpos() + inc.min(room));
}
