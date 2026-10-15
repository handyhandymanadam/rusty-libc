use crate::flock::locked;
use crate::file::{self, File as FILE};
use crate::scan::{self, MODE_C23_BIN, MODE_LEGACY_A, Src};
use crate::scan_api::scan_run_fmt;
use crate::wfile;
use core::ffi::{VaList, c_int};
use rusty_libc_wchar::wchar_t;

pub struct WFileSrc(*mut FILE);

impl WFileSrc {
    pub unsafe fn new(f: *mut FILE) -> WFileSrc {
        WFileSrc(f)
    }

    #[inline(always)]
    fn stream(&mut self) -> &mut FILE {
        unsafe { file::stream(self.0) }
    }
}

impl Src for WFileSrc {
    const WIDE: bool = true;
    fn get(&mut self) -> c_int {
        wfile::getwc_raw(self.stream()) as c_int
    }
    fn unget(&mut self, c: c_int) {
        wfile::ungetwc_raw(c as u32, self.stream());
    }
}

pub struct WStrSrc {
    p: *const u32,
}

impl WStrSrc {
    pub unsafe fn new(p: *const u32) -> WStrSrc {
        WStrSrc { p }
    }
}

impl Src for WStrSrc {
    const WIDE: bool = true;
    fn get(&mut self) -> c_int {
        let c = unsafe { *self.p };
        if c == 0 {
            scan::EOF
        } else {
            self.p = self.p.wrapping_add(1);
            c as c_int
        }
    }
    fn unget(&mut self, _c: c_int) {
        self.p = self.p.wrapping_sub(1);
    }
}

unsafe fn stream_scan(f: *mut FILE, format: *const wchar_t, va: &mut VaList, mode: u32) -> c_int {
    locked!(f, |s| {
        if !wfile::wide_ok(s) {
            return scan::EOF;
        }
        if s.flags & crate::file::F_READ == 0 {
            rusty_libc_core::errno::set(9);
            return scan::EOF;
        }
        let mut src = unsafe { WFileSrc::new(f) };
        unsafe { scan_run_fmt::<WFileSrc, u32>(&mut src, format as *const u32, va, mode) }
    })
}

macro_rules! wscanf_family {
    ($mode:expr, $fwscanf:ident, $wscanf:ident, $swscanf:ident, $vfwscanf:ident, $vwscanf:ident, $vswscanf:ident) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vfwscanf(f: *mut FILE, format: *const wchar_t, mut ap: VaList) -> c_int {
            unsafe { stream_scan(f, format, &mut ap, $mode) }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vwscanf(format: *const wchar_t, mut ap: VaList) -> c_int {
            unsafe { stream_scan(file::stdin_ptr(), format, &mut ap, $mode) }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $vswscanf(s: *const wchar_t, format: *const wchar_t, mut ap: VaList) -> c_int {
            let mut src = unsafe { WStrSrc::new(s as *const u32) };
            unsafe { scan_run_fmt::<WStrSrc, u32>(&mut src, format as *const u32, &mut ap, $mode) }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $fwscanf(f: *mut FILE, format: *const wchar_t, mut args: ...) -> c_int {
            unsafe { stream_scan(f, format, &mut args, $mode) }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $wscanf(format: *const wchar_t, mut args: ...) -> c_int {
            unsafe { stream_scan(file::stdin_ptr(), format, &mut args, $mode) }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $swscanf(s: *const wchar_t, format: *const wchar_t, mut args: ...) -> c_int {
            let mut src = unsafe { WStrSrc::new(s as *const u32) };
            unsafe { scan_run_fmt::<WStrSrc, u32>(&mut src, format as *const u32, &mut args, $mode) }
        }
    };
}

wscanf_family!(MODE_LEGACY_A, fwscanf, wscanf, swscanf, vfwscanf, vwscanf, vswscanf);
wscanf_family!(0, __isoc99_fwscanf, __isoc99_wscanf, __isoc99_swscanf, __isoc99_vfwscanf, __isoc99_vwscanf, __isoc99_vswscanf);
wscanf_family!(MODE_C23_BIN, __isoc23_fwscanf, __isoc23_wscanf, __isoc23_swscanf, __isoc23_vfwscanf, __isoc23_vwscanf, __isoc23_vswscanf);
