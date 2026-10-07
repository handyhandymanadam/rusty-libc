use crate::flock::locked;
use crate::file::{self, File as FILE};
use crate::scan::{self, MODE_C23_BIN, MODE_LEGACY_A, Src};
use crate::scan_api::scan_run_fmt;
use crate::wfile;
use core::ffi::{VaList, c_int};
use rusty_libc_wchar::wchar_t;

pub struct WFileSrc(pub *mut FILE);

impl Src for WFileSrc {
    const WIDE: bool = true;
    unsafe fn get(&mut self) -> c_int {
        unsafe { wfile::getwc_raw(self.0) as c_int }
    }
    unsafe fn unget(&mut self, c: c_int) {
        unsafe {
            wfile::ungetwc_raw(c as u32, self.0);
        }
    }
}

pub struct WStrSrc {
    p: *const u32,
}

impl WStrSrc {
    pub fn new(p: *const u32) -> WStrSrc {
        WStrSrc { p }
    }
}

impl Src for WStrSrc {
    const WIDE: bool = true;
    unsafe fn get(&mut self) -> c_int {
        unsafe {
            let c = *self.p;
            if c == 0 {
                scan::EOF
            } else {
                self.p = self.p.add(1);
                c as c_int
            }
        }
    }
    unsafe fn unget(&mut self, _c: c_int) {
        unsafe { self.p = self.p.sub(1) };
    }
}

unsafe fn stream_scan(f: *mut FILE, format: *const wchar_t, va: &mut VaList, mode: u32) -> c_int {
    unsafe { locked!(f, move || stream_scan_u(f, format, va, mode)) }
}

unsafe fn stream_scan_u(f: *mut FILE, format: *const wchar_t, va: &mut VaList, mode: u32) -> c_int {
    unsafe {
        if !wfile::wide_ok(f) {
            return scan::EOF;
        }
        scan_run_fmt::<WFileSrc, u32>(&mut WFileSrc(f), format as *const u32, va, mode)
    }
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
            unsafe { scan_run_fmt::<WStrSrc, u32>(&mut WStrSrc::new(s as *const u32), format as *const u32, &mut ap, $mode) }
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
            unsafe { scan_run_fmt::<WStrSrc, u32>(&mut WStrSrc::new(s as *const u32), format as *const u32, &mut args, $mode) }
        }
    };
}

wscanf_family!(MODE_LEGACY_A, fwscanf, wscanf, swscanf, vfwscanf, vwscanf, vswscanf);
wscanf_family!(0, __isoc99_fwscanf, __isoc99_wscanf, __isoc99_swscanf, __isoc99_vfwscanf, __isoc99_vwscanf, __isoc99_vswscanf);
wscanf_family!(MODE_C23_BIN, __isoc23_fwscanf, __isoc23_wscanf, __isoc23_swscanf, __isoc23_vfwscanf, __isoc23_vwscanf, __isoc23_vswscanf);
