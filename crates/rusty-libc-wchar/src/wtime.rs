//! `wcsftime` and `wcsftime_l`: the engine of `strftime` (rusty-libc-time) over wide characters. The
//! month and day names, the date and time formats, the era names and the alternative digits come
//! from the wide LC_TIME items of the locale (what glibc's wide build reads), counts and widths
//! are in wide characters, and the `^` and `#` flags use the locale's wide case mapping.
use crate::wchar_t;
use crate::wctype::{to_lower, to_lower_loc, to_upper, to_upper_loc};
use crate::wstring::locale_t;
use rusty_libc_core::locale::Loc;
use rusty_libc_time::calendar::Tm;
use rusty_libc_time::strftime::{WcOps, wcsftime_with};

fn up(c: u32, loc: Loc) -> u32 {
    if loc == Loc::CURRENT { to_upper(c) } else { to_upper_loc(c, loc) }
}

fn low(c: u32, loc: Loc) -> u32 {
    if loc == Loc::CURRENT { to_lower(c) } else { to_lower_loc(c, loc) }
}

/// `%Z`'s conversion of the zone name (see `Wc::mbs`) in the charset of `loc`. An ASCII name is the same in every
/// locale charset (C, UTF-8 and the ASCII-compatible others glibc's locales use), so only a name with other bytes looks
/// at the locale; for a locale other than the calling thread's, the conversion runs with `loc` installed as the thread's
/// locale for its duration (as glibc's `__mbsrtowcs_l` uses the locale's LC_CTYPE).
fn mbs(z: &[u8], out: Option<&mut [u32]>, loc: Loc) -> Option<usize> {
    if z.is_ascii() {
        return Some(match out {
            None => z.len(),
            Some(o) => {
                // the name, and its 0 if it fits
                let k = z.len().min(o.len());
                for (d, &b) in o.iter_mut().zip(&z[..k]) {
                    *d = u32::from(b);
                }
                if k == z.len()
                    && let Some(d) = o.get_mut(k)
                {
                    *d = 0;
                }
                k
            }
        });
    }
    if loc == Loc::CURRENT {
        return crate::mbyte::mbs_no_nul(z, out);
    }
    use rusty_libc_core::locale::{self, CatData};
    let prev = locale::thread();
    let target: *const *const CatData = if loc.raw() == locale::LC_GLOBAL_LOCALE { core::ptr::null() } else { loc.raw() as *const *const CatData };
    // SAFETY: a `Loc` other than CURRENT is LC_GLOBAL_LOCALE (installed as null: the global locale) or a live locale
    // object (its constructor's contract), which stays valid during the call.
    unsafe { locale::set_thread(target) };
    let r = crate::mbyte::mbs_no_nul(z, out);
    // SAFETY: `prev` is what was installed before (null or a locale object the program installed with uselocale).
    unsafe { locale::set_thread(prev) };
    r
}

/// (the functions as one reference: with the locale too, the 7th argument of `wcsftime_with` went on the stack and
/// `wcsftime` could not end in a jump)
static WC: WcOps = WcOps { up, low, mbs };

/// `size_t wcsftime(wchar_t *s, size_t maxsize, const wchar_t *format, const struct tm *tp)`: write
/// `tp` into `s` as `format` says, at most `maxsize` wide characters including the terminating 0.
/// Returns the length without the 0, or 0 if the result does not fit (the contents are then
/// undefined, as in glibc).
///
/// # Safety
/// `s` must be valid for `maxsize` wide characters, `format` NUL-terminated, `tp` a valid `struct tm`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsftime(s: *mut wchar_t, maxsize: usize, format: *const wchar_t, tp: *const Tm) -> usize {
    // SAFETY: forwarded contract (the engine's: output, NUL-terminated format, valid `struct tm`).
    unsafe { wcsftime_with(s.cast(), maxsize, format.cast(), tp, 0, &WC) }
}

/// As `wcsftime`, with the names and formats of the locale `loc`.
///
/// # Safety
/// As `wcsftime`; `loc` a valid `locale_t`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsftime_l(s: *mut wchar_t, maxsize: usize, format: *const wchar_t, tp: *const Tm, loc: locale_t) -> usize {
    // SAFETY: forwarded contract; `loc` is a locale_t.
    unsafe { wcsftime_with(s.cast(), maxsize, format.cast(), tp, loc as usize, &WC) }
}


// glibc's strong aliases of the `_l` functions (libstdc++ imports them by these names).
rusty_libc_core::tail_alias!(__wcsftime_l => wcsftime_l);
