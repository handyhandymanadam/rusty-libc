use crate::file::{self, F_READ, F_WRITE, File as FILE};
use crate::flock::locked;
use core::ffi::c_int;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fbufsize(f: *mut FILE) -> usize {
    unsafe { (*f).bufsize }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fpending(f: *mut FILE) -> usize {
    unsafe { if (*f).flags & file::F_WRMODE != 0 { (*f).wpos() } else { 0 } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __flbf(f: *mut FILE) -> c_int {
    unsafe { ((*f).flags & file::F_LBF) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadable(f: *mut FILE) -> c_int {
    unsafe { c_int::from((*f).flags & F_READ != 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwritable(f: *mut FILE) -> c_int {
    unsafe { c_int::from((*f).flags & F_WRITE != 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freading(f: *mut FILE) -> c_int {
    unsafe {
        let fl = (*f).flags;
        c_int::from(fl & F_WRITE == 0 || fl & file::F_RDMODE != 0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwriting(f: *mut FILE) -> c_int {
    unsafe {
        let fl = (*f).flags;
        c_int::from(fl & F_READ == 0 || fl & file::F_WRMODE != 0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fpurge(f: *mut FILE) {
    unsafe { locked!(f, move || file::purge(f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _flushlbf() {
    unsafe { file::flush_line_buffered_pub() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fsetlocking(f: *mut FILE, ty: c_int) -> c_int {
    unsafe {
        let old = if (*f).nolock { 2 } else { 1 };
        match ty {
            1 => (*f).nolock = false,
            2 => (*f).nolock = true,
            _ => {}
        }
        old
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fseterr(f: *mut FILE) {
    unsafe { (*f).flags |= file::F_ERR }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadahead(f: *mut FILE) -> usize {
    unsafe {
        if (*f).flags & file::F_WRMODE != 0 {
            return 0;
        }
        let buffered = if (*f).flags & file::F_RDMODE != 0 { (*f).rend() - (*f).rpos() } else { 0 };
        buffered + (*f).nunget()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadptr(f: *mut FILE, sizep: *mut usize) -> *const core::ffi::c_char {
    unsafe {
        if (*f).flags & (file::F_WRMODE | file::F_RDMODE) != file::F_RDMODE || (*f).nunget() > 0 || (*f).rpos() >= (*f).rend() {
            return core::ptr::null();
        }
        *sizep = (*f).rend() - (*f).rpos();
        (*f).buf.add((*f).rpos()).cast()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadptrinc(f: *mut FILE, inc: usize) {
    unsafe {
        let room = (*f).rend() - (*f).rpos();
        (*f).set_rpos((*f).rpos() + inc.min(room));
    }
}
