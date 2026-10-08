use crate::wchar_t;
use crate::wctype::{to_lower, to_upper};
use crate::wstring::locale_t;
use rusty_libc_time::calendar::Tm;
use rusty_libc_time::strftime::{Wc, wcsftime_with};

fn up(c: u32, loc: usize) -> u32 {
    if loc == 0 {
        to_upper(c)
    } else {
        unsafe { crate::wctype::towupper_l(c, loc as locale_t) }
    }
}

fn low(c: u32, loc: usize) -> u32 {
    if loc == 0 {
        to_lower(c)
    } else {
        unsafe { crate::wctype::towlower_l(c, loc as locale_t) }
    }
}

const WC: Wc = Wc { up, low, loc: 0 };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsftime(s: *mut wchar_t, maxsize: usize, format: *const wchar_t, tp: *const Tm) -> usize {
    unsafe { wcsftime_with(s.cast(), maxsize, format.cast(), tp, 0, WC) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsftime_l(s: *mut wchar_t, maxsize: usize, format: *const wchar_t, tp: *const Tm, loc: locale_t) -> usize {
    unsafe { wcsftime_with(s.cast(), maxsize, format.cast(), tp, loc as usize, WC) }
}


rusty_libc_core::tail_alias!(__wcsftime_l => wcsftime_l);
