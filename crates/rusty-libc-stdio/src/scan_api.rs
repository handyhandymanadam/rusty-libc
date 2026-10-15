use crate::file::{self, File as FILE};
use crate::flock::locked;
use crate::fmt::FmtChar;
use crate::scan::{self, MODE_C23_BIN, MODE_LEGACY_A, PtrArgs, Src, StrSrc};
use core::ffi::{VaList, c_char, c_int, c_void};

pub struct FileSrc(*mut FILE);

impl FileSrc {
    pub unsafe fn new(f: *mut FILE) -> FileSrc {
        FileSrc(f)
    }

    #[inline(always)]
    fn stream(&mut self) -> &mut FILE {
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
        if f.flags & file::F_READ == 0 {
            rusty_libc_core::errno::set(9);
            return false;
        }
        true
    }
}

pub struct VaPtrs<'a, 'f> {
    va: &'a mut VaList<'f>,
}

impl PtrArgs for VaPtrs<'_, '_> {
    #[inline]
    fn next(&mut self, _pos: usize) -> *mut c_void {
        unsafe { self.va.next_arg::<*mut c_void>() }
    }
}

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

pub unsafe fn scan_run<S: Src>(src: &mut S, fmt: *const c_char, va: &mut VaList, mode: u32) -> c_int {
    unsafe { scan_run_fmt::<S, u8>(src, fmt as *const u8, va, mode) }
}

pub unsafe fn scan_run_fmt<S: Src, F: FmtChar>(src: &mut S, f: *const F, va: &mut VaList, mode: u32) -> c_int {
    if !src.orient_ok() {
        return -1;
    }
    let maxpos = if unsafe { F::has_dollar(f) } { unsafe { max_position(f) } } else { 0 };
    if maxpos == 0 {
        return unsafe { scan::scan(src, f, &mut VaPtrs { va }, mode) };
    }
    let mut args = PosPtrs { pos: [core::ptr::null_mut(); 128], seq: 0 };
    for slot in args.pos.iter_mut().take(maxpos) {
        *slot = unsafe { va.next_arg::<*mut c_void>() };
    }
    unsafe { scan::scan(src, f, &mut args, mode) }
}

macro_rules! scanf_family {
    ($mode:expr, $fscanf:ident, $scanf:ident, $sscanf:ident, $vfscanf:ident, $vscanf:ident, $vsscanf:ident) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vfscanf(f: *mut FILE, format: *const c_char, mut ap: VaList) -> c_int {
            locked!(f, |_s| {
                let mut src = unsafe { FileSrc::new(f) };
                unsafe { scan_run(&mut src, format, &mut ap, $mode) }
            })
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vscanf(format: *const c_char, mut ap: VaList) -> c_int {
            let f = file::stdin_ptr();
            locked!(f, |_s| {
                let mut src = unsafe { FileSrc::new(f) };
                unsafe { scan_run(&mut src, format, &mut ap, $mode) }
            })
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vsscanf(s: *const c_char, format: *const c_char, mut ap: VaList) -> c_int {
            let mut src = unsafe { StrSrc::new(s as *const u8) };
            unsafe { scan_run(&mut src, format, &mut ap, $mode) }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $fscanf(f: *mut FILE, format: *const c_char, mut args: ...) -> c_int {
            locked!(f, |_s| {
                let mut src = unsafe { FileSrc::new(f) };
                unsafe { scan_run(&mut src, format, &mut args, $mode) }
            })
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $scanf(format: *const c_char, mut args: ...) -> c_int {
            let f = file::stdin_ptr();
            locked!(f, |_s| {
                let mut src = unsafe { FileSrc::new(f) };
                unsafe { scan_run(&mut src, format, &mut args, $mode) }
            })
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $sscanf(s: *const c_char, format: *const c_char, mut args: ...) -> c_int {
            let mut src = unsafe { StrSrc::new(s as *const u8) };
            unsafe { scan_run(&mut src, format, &mut args, $mode) }
        }
    };
}

scanf_family!(MODE_LEGACY_A, fscanf, scanf, sscanf, vfscanf, vscanf, vsscanf);
scanf_family!(0, __isoc99_fscanf, __isoc99_scanf, __isoc99_sscanf, __isoc99_vfscanf, __isoc99_vscanf, __isoc99_vsscanf);
scanf_family!(MODE_C23_BIN, __isoc23_fscanf, __isoc23_scanf, __isoc23_sscanf, __isoc23_vfscanf, __isoc23_vscanf, __isoc23_vsscanf);
