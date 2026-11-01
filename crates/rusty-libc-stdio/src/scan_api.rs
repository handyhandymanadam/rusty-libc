//! stdio.h formatted input: scanf, fscanf, sscanf and their `v` forms, in the three flavours glibc
//! exports (legacy `%as` allocation, C99, C23 binary prefix).
use crate::file::{self, File as FILE};
use crate::flock::locked;
use crate::fmt::FmtChar;
use crate::scan::{self, MODE_C23_BIN, MODE_LEGACY_A, PtrArgs, Src, StrSrc};
use core::ffi::{VaList, c_char, c_int, c_void};

/// A FILE as a character source. Built by the stream scanf functions from the caller's open stream, which they hold locked
/// for the whole call; each method borrows the stream for that call only.
pub struct FileSrc(*mut FILE);

impl FileSrc {
    /// # Safety
    /// `f` is an open stream that the calling thread may use (locked) while the source lives.
    pub unsafe fn new(f: *mut FILE) -> FileSrc {
        FileSrc(f)
    }

    #[inline(always)]
    fn stream(&mut self) -> &mut FILE {
        // SAFETY: `new`'s contract: an open stream, locked by the scanf call that made this source.
        unsafe { file::stream(self.0) }
    }
}

impl Src for FileSrc {
    fn get(&mut self) -> c_int {
        file::getc(self.stream())
    }
    fn unget(&mut self, c: c_int) {
        file::ungetc(c, self.stream());
    }
    fn peek(&mut self) -> (*const u8, usize) {
        let f = self.stream();
        if f.nunget() > 0 {
            return (core::ptr::null(), 0);
        }
        file::fill_buf(f).map_or((core::ptr::null(), 0), |w| (w.as_ptr(), w.len()))
    }
    fn advance(&mut self, n: usize) {
        file::consume(self.stream(), n);
    }
    fn orient_ok(&mut self) -> bool {
        let f = self.stream();
        if !file::narrow_ok(f) {
            return false;
        }
        // glibc's `ARGCHECK`, right after `ORIENT`: a stream that cannot be read fails with EBADF before anything
        // touches the stream (the error indicator stays clear)
        if f.flags & file::F_READ == 0 {
            rusty_libc_core::errno::set(9);
            return false;
        }
        true
    }
}

/// Pointer arguments taken one after another from a `va_list`.
pub struct VaPtrs<'a, 'f> {
    va: &'a mut VaList<'f>,
}

impl PtrArgs for VaPtrs<'_, '_> {
    #[inline]
    fn next(&mut self, _pos: usize) -> *mut c_void {
        // SAFETY: the scanf caller's contract: every conversion that stores takes a pointer argument, read in order.
        unsafe { self.va.next_arg::<*mut c_void>() }
    }
}

/// Pointer arguments for formats that use `%N$`: every referenced position is read up front.
pub struct PosPtrs {
    pos: [*mut c_void; 128],
    seq: usize,
}

impl PtrArgs for PosPtrs {
    fn next(&mut self, pos: usize) -> *mut c_void {
        let n = if pos == 0 {
            self.seq += 1;
            self.seq
        } else {
            pos
        };
        if (1..=128).contains(&n) { self.pos[n - 1] } else { core::ptr::null_mut() }
    }
}

/// Highest `%N$` position used by the format (0 if none).
///
/// # Safety
/// `fmt` is NUL-terminated.
pub(crate) unsafe fn max_position<F: FmtChar>(fmt: *const F) -> usize {
    let mut f = 0usize;
    let mut max = 0usize;
    while fmt_at!(fmt, f) != 0 {
        if fmt_at!(fmt, f) == b'%' {
            f += 1;
            if fmt_at!(fmt, f) == b'%' {
                f += 1;
                continue;
            }
            let mut n = 0usize;
            let mut digits = false;
            while fmt_at!(fmt, f).is_ascii_digit() {
                n = n.saturating_mul(10).saturating_add(usize::from(fmt_at!(fmt, f) - b'0'));
                digits = true;
                f += 1;
            }
            if digits && fmt_at!(fmt, f) == b'$' && n > max {
                max = n;
            }
        } else {
            f += 1;
        }
    }
    max
}

/// Run the engine over `src`, reading arguments from `va`.
///
/// # Safety
/// As for `scanf`.
pub unsafe fn scan_run<S: Src>(src: &mut S, fmt: *const c_char, va: &mut VaList, mode: u32) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { scan_run_fmt::<S, u8>(src, fmt as *const u8, va, mode) }
}

/// `scan_run` for either character type of format.
///
/// # Safety
/// As for `scanf`; `f` is NUL-terminated.
pub unsafe fn scan_run_fmt<S: Src, F: FmtChar>(src: &mut S, f: *const F, va: &mut VaList, mode: u32) -> c_int {
    if !src.orient_ok() {
        return -1;
    }
    // only a format with a `$` can use positional arguments
    // SAFETY: the caller's contract: `f` is NUL-terminated (both scans read to its NUL).
    let maxpos = if unsafe { F::has_dollar(f) } { unsafe { max_position(f) } } else { 0 };
    if maxpos == 0 {
        // SAFETY: the caller's contract: the format and the pointer arguments.
        return unsafe { scan::scan(src, f, &mut VaPtrs { va }, mode) };
    }
    let mut args = PosPtrs { pos: [core::ptr::null_mut(); 128], seq: 0 };
    for slot in args.pos.iter_mut().take(maxpos) {
        // SAFETY: the caller's contract: a pointer argument for every position the format names.
        *slot = unsafe { va.next_arg::<*mut c_void>() };
    }
    // SAFETY: the caller's contract.
    unsafe { scan::scan(src, f, &mut args, mode) }
}

macro_rules! scanf_family {
    ($mode:expr, $fscanf:ident, $scanf:ident, $sscanf:ident, $vfscanf:ident, $vscanf:ident, $vsscanf:ident) => {
        /// # Safety
        /// `f` must be an open stream; `format` must match the pointer arguments.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vfscanf(f: *mut FILE, format: *const c_char, mut ap: VaList) -> c_int {
            locked!(f, |_s| {
                // SAFETY: an open stream (the caller's contract, or `stdin`), held locked for the whole call.
                let mut src = unsafe { FileSrc::new(f) };
                // SAFETY: the caller's contract: the format and its pointer arguments.
                unsafe { scan_run(&mut src, format, &mut ap, $mode) }
            })
        }
        /// # Safety
        /// As the `v` stream form.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vscanf(format: *const c_char, mut ap: VaList) -> c_int {
            let f = file::stdin_ptr();
            locked!(f, |_s| {
                // SAFETY: an open stream (the caller's contract, or `stdin`), held locked for the whole call.
                let mut src = unsafe { FileSrc::new(f) };
                // SAFETY: the caller's contract: the format and its pointer arguments.
                unsafe { scan_run(&mut src, format, &mut ap, $mode) }
            })
        }
        /// # Safety
        /// `s` and `format` must be NUL-terminated.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vsscanf(s: *const c_char, format: *const c_char, mut ap: VaList) -> c_int {
            // SAFETY: the caller's contract: `s` is NUL-terminated.
            let mut src = unsafe { StrSrc::new(s as *const u8) };
            // SAFETY: the caller's contract: the format and its pointer arguments.
            unsafe { scan_run(&mut src, format, &mut ap, $mode) }
        }
        /// # Safety
        /// As the `v` stream form.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $fscanf(f: *mut FILE, format: *const c_char, mut args: ...) -> c_int {
            locked!(f, |_s| {
                // SAFETY: an open stream (the caller's contract, or `stdin`), held locked for the whole call.
                let mut src = unsafe { FileSrc::new(f) };
                // SAFETY: the caller's contract: the format and its pointer arguments.
                unsafe { scan_run(&mut src, format, &mut args, $mode) }
            })
        }
        /// # Safety
        /// As the `v` stream form.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $scanf(format: *const c_char, mut args: ...) -> c_int {
            let f = file::stdin_ptr();
            locked!(f, |_s| {
                // SAFETY: an open stream (the caller's contract, or `stdin`), held locked for the whole call.
                let mut src = unsafe { FileSrc::new(f) };
                // SAFETY: the caller's contract: the format and its pointer arguments.
                unsafe { scan_run(&mut src, format, &mut args, $mode) }
            })
        }
        /// # Safety
        /// As the `v` string form.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $sscanf(s: *const c_char, format: *const c_char, mut args: ...) -> c_int {
            // SAFETY: the caller's contract: `s` is NUL-terminated.
            let mut src = unsafe { StrSrc::new(s as *const u8) };
            // SAFETY: the caller's contract: the format and its pointer arguments.
            unsafe { scan_run(&mut src, format, &mut args, $mode) }
        }
    };
}

scanf_family!(MODE_LEGACY_A, fscanf, scanf, sscanf, vfscanf, vscanf, vsscanf);
scanf_family!(0, __isoc99_fscanf, __isoc99_scanf, __isoc99_sscanf, __isoc99_vfscanf, __isoc99_vscanf, __isoc99_vsscanf);
scanf_family!(MODE_C23_BIN, __isoc23_fscanf, __isoc23_scanf, __isoc23_sscanf, __isoc23_vfscanf, __isoc23_vscanf, __isoc23_vsscanf);
