//! `strftime`, `strptime` and `getdate`, in the current locale (or the `locale_t` of the `_l` forms):
//! day and month names, the `%c %x %X %r %p` formats, eras (`%E`) and alternative digits (`%O`)
//! come from LC_TIME (see `timeloc`).
//!
//! The behaviour is glibc 2.43's, down to the odd corners: the GNU flags `_ - 0 ^ #` and field
//! width, the `E` and `O` modifiers (accepted for the conversions glibc accepts them for; the C
//! locale has no eras or alternative digits), an unknown conversion copied through as written,
//! `0` returned when the buffer is too small (the buffer then holds a partial result), `%z`
//! empty when `tm_isdst` is negative, `%Z` taken from `tm_zone` or else from `tzname`.
//! `strptime` keeps glibc's leniency (white space matches any amount, numbers skip leading white
//! space, names are case-insensitive prefixes) and its state machine for the `E`/`O` modifiers.
//! `getdate` uses `strptime` in the current locale.
//!
//! Thin unsafe shell, safe core: the exported functions turn their C strings and buffers into slices once (core's `ffi`),
//! and the engines (`strftime_internal`, `strptime_internal`) work on slices with indexes: a C pointer walk `*p`, `p + 1`
//! became `at(s, i)`, `i + 1`, where a byte past the end of the slice reads as the NUL the C string had there (Scylla,
//! Fromherz and Protzenko, p.10: pointer arithmetic as slice splits; Emre et al. p.8). Unsafe here: those boundary
//! conversions, `tm_zone` (a C string pointer inside `struct tm`) for `%Z`, and the static results of `getdate`.
use crate::calendar::{self, Tm};
use crate::clock::LocaleT;
use crate::mbuf::MBuf;
use crate::sys;
use crate::timeloc::{self, TimeLoc, no_nul};
use crate::tz;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicI32, Ordering::Relaxed};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::ffi;
use rusty_libc_core::locale::Loc;
use rusty_libc_stdlib::zstr::{Unit, ZStr};
use timeloc::Fmt;

/// Upper-case wide or narrow characters in place (the `^` flag on a sub-format's text).
fn upcase<C: Ch>(s: &mut [C], tl: &TimeLoc, wc: Wc) {
    for c in s {
        *c = c.upper(tl, wc);
    }
}

/// Room for a NUL-terminated copy of a string (see [`with_nul`]): a stack array for short ones, a malloc block otherwise.
struct NulCopy<C: Unit> {
    stack: Option<[C; 128]>,
    heap: Option<MBuf<C>>,
}

impl<C: Unit> NulCopy<C> {
    fn new() -> Self {
        NulCopy { stack: None, heap: None }
    }

    /// A cursor over a NUL-terminated copy of `s`, valid while `self` is; None if a long copy cannot be allocated.
    fn z(&mut self, s: &[C]) -> Option<ZStr<'_, C>> {
        let n = s.len();
        let b: &mut [C] = if n < 128 {
            &mut self.stack.insert([C::NUL; 128])[..=n]
        } else {
            self.heap.insert(MBuf::filled(n + 1, C::NUL)?)
        };
        b[..n].copy_from_slice(s);
        ZStr::from_nul_terminated(b)
    }
}

/// Run `f` on a NUL-terminated copy of `s` (a locale's format, a template line: the string up to its first NUL) for the
/// engines, which read formats through a [`ZStr`] cursor: on the stack when short, else in a malloc block (None if that
/// allocation fails). The C locale's formats and the C callers' strings need no copy.
fn with_nul<C: Unit, R>(s: &[C], f: impl FnOnce(ZStr<'_, C>) -> R) -> Option<R> {
    NulCopy::new().z(s).map(f)
}

fn isleap(y: i32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

// ------------------------------------------------------------------ strftime

/// Days from the first day of the first ISO week of this year to `yday` (weekday `wday`).
fn iso_week_days(yday: i32, wday: i32) -> i32 {
    let big_enough_multiple_of_7 = (366 / 7 + 2) * 7;
    // (wrapping: the fields may hold any int; glibc's compiled code wraps the same way)
    yday.wrapping_sub(yday.wrapping_sub(wday).wrapping_add(4 + big_enough_multiple_of_7) % 7).wrapping_add(4 - 1)
}

/// Copy a byte run; short runs with overlapping word moves, no call (`dst` and `src` have the same length).
#[inline(always)]
fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    let n = src.len();
    let dst = &mut dst[..n];
    if n <= 16 {
        if n >= 8 {
            let (a, b) = (u64::from_ne_bytes(src[..8].try_into().unwrap()), u64::from_ne_bytes(src[n - 8..].try_into().unwrap()));
            dst[..8].copy_from_slice(&a.to_ne_bytes());
            dst[n - 8..].copy_from_slice(&b.to_ne_bytes());
        } else if n >= 4 {
            let (a, b) = (u32::from_ne_bytes(src[..4].try_into().unwrap()), u32::from_ne_bytes(src[n - 4..].try_into().unwrap()));
            dst[..4].copy_from_slice(&a.to_ne_bytes());
            dst[n - 4..].copy_from_slice(&b.to_ne_bytes());
        } else if n >= 2 {
            let (a, b) = (u16::from_ne_bytes(src[..2].try_into().unwrap()), u16::from_ne_bytes(src[n - 2..].try_into().unwrap()));
            dst[..2].copy_from_slice(&a.to_ne_bytes());
            dst[n - 2..].copy_from_slice(&b.to_ne_bytes());
        } else if n == 1 {
            dst[0] = src[0];
        }
    } else {
        dst.copy_from_slice(src);
    }
}

/// Copy a run of wide characters; runs up to 16 with overlapping fixed-size moves, no call (`dst` at least as long as `src`).
#[inline(always)]
fn copy_units32(dst: &mut [u32], src: &[u32]) {
    let n = src.len();
    let dst = &mut dst[..n];
    #[inline(always)]
    fn mv<const K: usize>(dst: &mut [u32], src: &[u32], at: usize) {
        let a: [u32; K] = src[at..at + K].try_into().unwrap();
        dst[at..at + K].copy_from_slice(&a);
    }
    if n <= 16 {
        if n >= 8 {
            mv::<4>(dst, src, 0);
            mv::<4>(dst, src, 4);
            mv::<4>(dst, src, n - 8);
            mv::<4>(dst, src, n - 4);
        } else if n >= 4 {
            mv::<4>(dst, src, 0);
            mv::<4>(dst, src, n - 4);
        } else if n >= 2 {
            mv::<2>(dst, src, 0);
            mv::<2>(dst, src, n - 2);
        } else if n == 1 {
            dst[0] = src[0];
        }
    } else {
        dst.copy_from_slice(src);
    }
}

/// The calendar arithmetic of the numeric conversions C u U W y g G V, kept out of line so the
/// optimizer does not compute all of it in front of the format loop.
#[inline(never)]
fn tm_number(fc: u8, tp: &Tm) -> i32 {
    match fc {
        b'C' => {
            let year = tp.tm_year.wrapping_add(1900);
            year / 100 - (year % 100 < 0) as i32
        }
        b'u' => tp.tm_wday.wrapping_add(6) % 7 + 1,
        b'U' => tp.tm_yday.wrapping_sub(tp.tm_wday).wrapping_add(7) / 7,
        b'W' => tp.tm_yday.wrapping_sub(tp.tm_wday.wrapping_add(6) % 7).wrapping_add(7) / 7,
        b'y' => (tp.tm_year % 100 + 100) % 100,
        _ => {
            let mut year = tp.tm_year.wrapping_add(1900);
            let mut days = iso_week_days(tp.tm_yday, tp.tm_wday);
            if days < 0 {
                year = year.wrapping_sub(1);
                days = iso_week_days(tp.tm_yday.wrapping_add(365 + isleap(year) as i32), tp.tm_wday);
            } else {
                let d = iso_week_days(tp.tm_yday.wrapping_sub(365 + isleap(year) as i32), tp.tm_wday);
                if d >= 0 {
                    year = year.wrapping_add(1);
                    days = d;
                }
            }
            match fc {
                b'g' => (year % 100 + 100) % 100,
                b'G' => year,
                _ => days / 7 + 1,
            }
        }
    }
}

/// A locale text: in the locale data or a built-in table (`Static`), or widened into the caller's scratch array (`Tmp`,
/// its length). Holds no borrow, so the format engine can keep it while it uses the scratch array for other texts.
#[derive(Clone, Copy)]
pub enum Text<C: 'static> {
    Static(&'static [C]),
    Tmp(usize),
}

impl<C: Copy> Text<C> {
    #[inline(always)]
    fn get<'a>(&self, tmp: &'a [C; TMP]) -> &'a [C] {
        match *self {
            Text::Static(s) => s,
            Text::Tmp(n) => &tmp[..n],
        }
    }
    #[inline(always)]
    fn len(&self) -> usize {
        match *self {
            Text::Static(s) => s.len(),
            Text::Tmp(n) => n,
        }
    }
}

/// Size of the scratch array for widened built-in texts: the C locale's longest text (its date and time format) is 20
/// characters.
const TMP: usize = 32;

/// A sub-format (`%c`, `%T` ...) as the engine runs it: a NUL-terminated string read in place (the C locale's built-in
/// formats), the widened copy in the scratch array (`Tmp`, its length; the NUL follows), or a locale item as a slice, which
/// is run on a NUL-terminated copy.
#[derive(Clone, Copy)]
pub enum SubF<C: Unit + 'static> {
    Z(ZStr<'static, C>),
    Tmp(usize),
    S(&'static [C]),
}

#[derive(Clone, Copy)]
enum Next<C: Unit + 'static> {
    Switch,
    /// digits, value, space padding by default
    Number(i32, i32, bool),
    Sub(SubF<C>),
    Bad,
}

/// Case mapping and multibyte conversion of wide characters, supplied by the caller of `wcsftime` (the tables live in
/// rusty-libc-wchar): `up(c, loc)` and `low(c, loc)` map `c` in the locale `loc` (a checked locale argument, FIXLIST
/// #103); `mbs(z, out, loc)` is glibc's `__mbsrtowcs_l(out, &z, out.len(), &state, loc)` on the C string whose bytes
/// before the NUL are `z`: it writes up to `out.len()` wide characters, and the terminating 0 too if it fits, and returns how many
/// it wrote without the 0 (with `out` None: the length); None, with errno EILSEQ, for an invalid sequence (the characters
/// before it are written). `%Z` of `wcsftime` converts the zone name with it.
/// (The functions sit behind one reference, `ops`: the engines take a `Wc` by value, and two words travel in registers.)
#[derive(Clone, Copy)]
pub struct Wc {
    pub ops: &'static WcOps,
    pub loc: Loc,
}

/// The functions of a [`Wc`].
pub struct WcOps {
    pub up: fn(u32, Loc) -> u32,
    pub low: fn(u32, Loc) -> u32,
    pub mbs: Mbs,
}

/// [`WcOps::mbs`]: (name bytes, output, locale) -> characters written.
pub type Mbs = fn(&[u8], Option<&mut [u32]>, Loc) -> Option<usize>;

fn same(c: u32, _loc: Loc) -> u32 {
    c
}

fn no_mbs(_z: &[u8], _out: Option<&mut [u32]>, _loc: Loc) -> Option<usize> {
    None
}

/// What `strftime` passes: the narrow case mapping comes from the `TimeLoc`; no conversion (only `wcsftime` converts).
const NARROW: Wc = Wc { ops: &WcOps { up: same, low: same, mbs: no_mbs }, loc: Loc::CURRENT };

/// errno of a `wcsftime` whose `%Z` does not fit.
const ERANGE: i32 = 34;

/// True when `wcsftime` would read a day or month name for this `tm` out of glibc's range checks: glibc 2.43 then copies
/// the narrow literal `"?"` as a wide string (`(const wchar_t *) "?"`, its `a_wkday`/`f_wkday`/`a_month`/`f_month`
/// macros), that is the bytes of that literal and whatever follows it in glibc's read-only data, up to a 4-byte zero
/// (2,865 characters in Fedora's 2.43 build). We match only its observable result for real buffers: 0 returned, errno
/// untouched, the buffer holding what came before the name (glibc's room check fails before it writes the name). We never
/// read memory past our own data to imitate those characters: their content and number depend on glibc's build, and a
/// caller's buffer longer than them (where glibc would succeed with them as text) is not imitated either.
#[inline(always)]
fn wide_name_garbage(tp: &Tm) -> bool {
    !(0..=6).contains(&rv(&tp.tm_wday)) || !(0..=11).contains(&rv(&tp.tm_mon))
}

/// A locale text `strftime` and `wcsftime` take from LC_TIME.
#[derive(Clone, Copy)]
pub enum It<'a> {
    AbDay(usize),
    Day(usize),
    AbMon(usize),
    Mon(usize),
    AltMon(usize),
    AbAltMon(usize),
    AmPm(bool),
    DTFmt,
    DFmt,
    TFmt,
    TFmtAmpm,
    EraDTFmt,
    EraDFmt,
    EraTFmt,
    EraName(&'a timeloc::Era),
    EraFormat(&'a timeloc::Era),
    AltDigit(u32),
    /// A built-in text (NUL-terminated, like a format).
    Lit(&'static [u8]),
}

/// One character unit of the output: `u8` for `strftime`, `u32` (`wchar_t`) for `wcsftime`. The two
/// differ in the locale items they read (narrow or wide) and in how they map case; the format
/// characters that matter are ASCII, everything else is copied through.
pub trait Ch: Copy + 'static + Unit {
    /// True for `wchar_t` units.
    const WIDE: bool;
    /// The ASCII value of the unit, 0x80 for anything else.
    fn asc(self) -> u8;
    fn from_u8(b: u8) -> Self;
    fn lower(self, tl: &TimeLoc, wc: Wc) -> Self;
    fn upper(self, tl: &TimeLoc, wc: Wc) -> Self;
    /// A locale text; `tmp` holds a widened copy of a built-in text.
    fn text(tl: &TimeLoc, it: It, tmp: &mut [Self; TMP]) -> Text<Self>;
    /// A locale text used as a sub-format.
    fn subfmt(tl: &TimeLoc, it: It, tmp: &mut [Self; TMP]) -> SubF<Self>;
    /// Copy `src` into `dst` (same length).
    fn copy(dst: &mut [Self], src: &[Self]);
    /// Copy ASCII bytes into `dst` (same length), widened for `wcsftime`.
    fn copy_ascii(dst: &mut [Self], src: &[u8]);
    /// The units as wide characters (None for `u8`).
    fn as_wide(s: &mut [Self]) -> Option<&mut [u32]>;
}

#[inline(never)]
fn narrow_text(tl: &TimeLoc, it: It) -> &'static [u8] {
    match it {
        It::AbDay(i) => tl.abday(i),
        It::Day(i) => tl.day(i),
        It::AbMon(i) => tl.abmon(i),
        It::Mon(i) => tl.mon(i),
        It::AltMon(i) => tl.altmon(i),
        It::AbAltMon(i) => tl.abaltmon(i),
        It::AmPm(pm) => tl.ampm(pm),
        It::DTFmt => tl.d_t_fmt(),
        It::DFmt => tl.d_fmt(),
        It::TFmt => tl.t_fmt(),
        It::TFmtAmpm => tl.t_fmt_ampm(),
        It::EraDTFmt => tl.era_d_t_fmt(),
        It::EraDFmt => tl.era_d_fmt(),
        It::EraTFmt => tl.era_t_fmt(),
        It::EraName(e) => e.name,
        It::EraFormat(e) => e.format,
        It::AltDigit(n) => tl.alt_digit(n).unwrap_or(b""),
        It::Lit(l) => no_nul(l),
    }
}

impl Ch for u8 {
    const WIDE: bool = false;
    #[inline(always)]
    fn asc(self) -> u8 {
        self
    }
    #[inline(always)]
    fn from_u8(b: u8) -> u8 {
        b
    }
    #[inline(always)]
    fn lower(self, tl: &TimeLoc, _wc: Wc) -> u8 {
        tl.tolower(self)
    }
    #[inline(always)]
    fn upper(self, tl: &TimeLoc, _wc: Wc) -> u8 {
        tl.toupper(self)
    }
    #[inline(always)]
    fn subfmt(tl: &TimeLoc, it: It, _tmp: &mut [u8; TMP]) -> SubF<u8> {
        // the built-in formats in place: they carry their NUL
        let z: Option<&'static core::ffi::CStr> = match it {
            It::Lit(l) => {
                if let Some(z) = ZStr::from_nul_terminated(l) {
                    return SubF::Z(z);
                }
                None
            }
            _ if !tl.is_c() => None,
            It::DTFmt => Some(timeloc::C_D_T_FMT_Z),
            It::DFmt => Some(timeloc::C_D_FMT_Z),
            It::TFmt => Some(timeloc::C_T_FMT_Z),
            It::TFmtAmpm => Some(timeloc::C_T_FMT_AMPM_Z),
            _ => None,
        };
        match z {
            Some(z) => SubF::Z(ZStr::from(z)),
            None => SubF::S(narrow_text(tl, it)),
        }
    }
    #[inline(always)]
    fn text(tl: &TimeLoc, it: It, _tmp: &mut [u8; TMP]) -> Text<u8> {
        // the common names of the C locale straight from the tables; everything else out of line
        if tl.is_c() {
            let sl: Option<&'static [u8]> = match it {
                It::AbDay(i) => Some(tl.abday(i)),
                It::Day(i) => Some(tl.day(i)),
                It::AbMon(i) => Some(tl.abmon(i)),
                It::Mon(i) => Some(tl.mon(i)),
                It::AmPm(pm) => Some(tl.ampm(pm)),
                _ => None,
            };
            if let Some(sl) = sl {
                return Text::Static(sl);
            }
        }
        Text::Static(narrow_text(tl, it))
    }
    #[inline(always)]
    fn copy(dst: &mut [u8], src: &[u8]) {
        copy_bytes(dst, src)
    }
    #[inline(always)]
    fn copy_ascii(dst: &mut [u8], src: &[u8]) {
        copy_bytes(dst, src)
    }
    fn as_wide(_s: &mut [u8]) -> Option<&mut [u32]> {
        None
    }
}

impl Ch for u32 {
    const WIDE: bool = true;
    #[inline(always)]
    fn asc(self) -> u8 {
        if self < 128 { self as u8 } else { 0x80 }
    }
    #[inline(always)]
    fn from_u8(b: u8) -> u32 {
        u32::from(b)
    }
    fn lower(self, _tl: &TimeLoc, wc: Wc) -> u32 {
        (wc.ops.low)(self, wc.loc)
    }
    fn upper(self, _tl: &TimeLoc, wc: Wc) -> u32 {
        (wc.ops.up)(self, wc.loc)
    }
    fn subfmt(tl: &TimeLoc, it: It, tmp: &mut [u32; TMP]) -> SubF<u32> {
        match Self::text(tl, it, tmp) {
            Text::Static(s) => SubF::S(s),
            // (`text` left the NUL after the widened copy)
            Text::Tmp(n) => SubF::Tmp(n),
        }
    }
    fn text(tl: &TimeLoc, it: It, tmp: &mut [u32; TMP]) -> Text<u32> {
        use rusty_libc_core::locale::idx;
        // the common names of the C locale from the wide tables (as the narrow `text`); `get` keeps an index out of the
        // table on the general path below
        if tl.is_c() {
            let sl: Option<&&'static [u32]> = match it {
                It::AbDay(i) => timeloc::W_AB_WEEKDAY.get(i),
                It::Day(i) => timeloc::W_WEEKDAY.get(i),
                It::AbMon(i) | It::AbAltMon(i) => timeloc::W_AB_MONTH.get(i),
                It::Mon(i) | It::AltMon(i) => timeloc::W_MONTH.get(i),
                It::AmPm(pm) => Some(&timeloc::W_AMPM[pm as usize]),
                _ => None,
            };
            if let Some(&sl) = sl {
                return Text::Static(sl);
            }
        }
        let wide = match it {
            It::AbDay(i) => Some(idx::WABDAY_1 + i),
            It::Day(i) => Some(idx::WDAY_1 + i),
            It::AbMon(i) => Some(idx::WABMON_1 + i),
            It::Mon(i) => Some(idx::WMON_1 + i),
            It::AltMon(i) => Some(idx::ALTMON_1 + 12 + i),
            It::AbAltMon(i) => Some(idx::ABALTMON_1 + 12 + i),
            It::AmPm(pm) => Some(idx::WAM_STR + pm as usize),
            It::DTFmt => Some(idx::WD_T_FMT),
            It::DFmt => Some(idx::WD_T_FMT + 1),
            It::TFmt => Some(idx::WD_T_FMT + 2),
            It::TFmtAmpm => Some(idx::WD_T_FMT + 3),
            It::EraDTFmt => Some(idx::WERA_D_T_FMT),
            It::EraDFmt => Some(idx::WERA_D_FMT),
            It::EraTFmt => Some(idx::WERA_T_FMT),
            _ => None,
        };
        if let Some(ix) = wide
            && let Some(r) = tl.wide_item(ix)
        {
            return Text::Static(r);
        }
        match it {
            It::EraName(e) => return Text::Static(e.wname),
            It::EraFormat(e) => return Text::Static(e.wformat),
            It::AltDigit(n) => return Text::Static(tl.walt_digit(n).unwrap_or(&[])),
            _ => {}
        }
        // the C locale (no data): the narrow built-in text, widened
        let narrow = narrow_text(tl, it);
        let n = narrow.len().min(tmp.len() - 1);
        for (t, &b) in tmp.iter_mut().zip(&narrow[..n]) {
            *t = u32::from(b);
        }
        tmp[n] = 0;
        Text::Tmp(n)
    }
    #[inline(always)]
    fn copy(dst: &mut [u32], src: &[u32]) {
        copy_units32(dst, src)
    }
    #[inline(always)]
    fn copy_ascii(dst: &mut [u32], src: &[u8]) {
        for (d, &b) in dst.iter_mut().zip(src) {
            *d = u32::from(b);
        }
    }
    fn as_wide(s: &mut [u32]) -> Option<&mut [u32]> {
        Some(s)
    }
}

/// Write copies of the ASCII character `b` into `dst`. Out of line: inlined, the vectorized loop's set-up (from the field
/// width) was hoisted in front of the engine's dispatch loop, and the values it kept live there were spilled and copied
/// on every conversion.
#[inline(never)]
fn fill<C: Ch>(dst: &mut [C], b: u8) {
    for d in dst {
        *d = C::from_u8(b);
    }
}

/// [`fill`] with the one-unit case (a number's single padding zero, `%d` of 9 say) written in place: no call.
#[inline(always)]
fn pad_units<C: Ch>(dst: &mut [C], b: u8) {
    if let [d] = dst {
        *d = C::from_u8(b);
    } else {
        fill(dst, b);
    }
}

/// "00" .. "99" for the two-digit steps of the number conversion.
const DIGIT_PAIRS: [u8; 200] = {
    let mut t = [0u8; 200];
    let mut k = 0;
    while k < 100 {
        t[2 * k] = b'0' + (k / 10) as u8;
        t[2 * k + 1] = b'0' + (k % 10) as u8;
        k += 1;
    }
    t
};

/// A volatile read: keeps the compiler from loading (and pre-computing from) every field of the `tm` at the
/// top of `strftime_internal` (about 40 spilled values per call); each conversion reads what it needs.
#[inline(always)]
fn rv<T: Copy>(r: &T) -> T {
    // SAFETY: `r` is a reference, so it is valid, aligned and initialised for a read.
    unsafe { core::ptr::read_volatile(r) }
}

/// Write `tp` into `s` (None to only count) following the NUL-terminated format at `fz`, at most `maxsize` units
/// including the NUL (with `s`, `maxsize` is its length). Returns the length, or 0 if it does not fit.
///
/// The output is kept as the part of `s` not yet written (`out`): a room check against its length leaves the writes after
/// it without bounds checks of their own.
#[allow(clippy::too_many_arguments)]
fn strftime_internal<C: Ch>(s: Option<&mut [C]>, maxsize: usize, mut fz: ZStr<'_, C>, tp: &Tm, tzset_called: &mut bool, tl: &TimeLoc, wc: Wc, yr_spec: u8) -> usize {
    let mut yr_spec = yr_spec;
    // the fields are read with `rv` where a conversion needs them: plain reads let the compiler copy about 40
    // loop-invariant values (year + 1900, hour12, ...) into the frame on every call
    let mut zone: *const c_char = rv(&tp.tm_zone);
    macro_rules! hour12 {
        () => {{
            let h = rv(&tp.tm_hour);
            if h > 12 { h - 12 } else if h == 0 { 12 } else { h }
        }};
    }
    let mut i = 0usize;
    // the output not written yet (`s[i..]`)
    let mut out = s;
    // buffers for numbers and widened texts (rewritten before each use; set up once per call)
    let mut buf = [0u8; 24];
    let mut tmp = [C::from_u8(0); TMP];

    while !fz.at_end() {
        let mut pad: u8 = 0;
        let mut width: i32 = -1;
        let mut to_lowcase = false;
        let mut to_uppcase = false;
        let mut change_case = false;

        // Room left for output: the length of what is not written yet, or `maxsize - i` when only counting.
        macro_rules! room {
            () => {
                match &out {
                    Some(o) => o.len(),
                    None => maxsize.wrapping_sub(i),
                }
            };
        }
        // `add(n, body)`: room check, padding to `width`, then the body writes `n` units at the start of `q` (the rest of
        // the output from there on).
        macro_rules! add {
            ($n:expr, |$q:ident| $body:expr) => {{
                let n: i32 = $n as i32;
                let delta = width - n;
                let incr = n + if delta > 0 { delta } else { 0 };
                match out.take() {
                    Some(o) => {
                        // (`o.len()` is `maxsize - i`)
                        if (incr as usize) >= o.len() {
                            return 0;
                        }
                        let mut at = 0;
                        if delta > 0 {
                            pad_units(&mut o[..delta as usize], if pad == b'0' { b'0' } else { b' ' });
                            at = delta as usize;
                        }
                        {
                            let $q = &mut o[at..];
                            $body;
                        }
                        out = Some(&mut o[incr as usize..]);
                    }
                    None => {
                        if (incr as usize) >= maxsize.wrapping_sub(i) {
                            return 0;
                        }
                    }
                }
                i += incr as usize;
            }};
        }
        // glibc's wide "?" name (see `wide_name_garbage`): longer than any buffer we model, so the room check fails
        // before anything is written (glibc's too, for any buffer up to its 2,865 characters); only counting, it counts
        // as i32::MAX units, so a sub-format holding it does not fit either.
        macro_rules! garbage {
            () => {{
                if out.is_some() || (i32::MAX as usize) >= maxsize.wrapping_sub(i) {
                    return 0;
                }
                i += i32::MAX as usize;
            }};
        }
        macro_rules! cpy {
            ($src:expr) => {{
                let src: &[C] = $src;
                let nn = src.len();
                add!(nn, |q| {
                    if !to_lowcase && !to_uppcase {
                        C::copy(&mut q[..nn], src);
                    } else {
                        for (d, &c) in q.iter_mut().zip(src) {
                            *d = if to_lowcase { c.lower(tl, wc) } else { c.upper(tl, wc) };
                        }
                    }
                });
            }};
        }
        // The same for ASCII bytes (digits, the zone name), widened for `wcsftime`.
        macro_rules! cpyb {
            ($src:expr) => {{
                let src: &[u8] = $src;
                let nn = src.len();
                add!(nn, |q| {
                    if !to_lowcase && !to_uppcase {
                        C::copy_ascii(&mut q[..nn], src);
                    } else {
                        for (d, &b) in q.iter_mut().zip(src) {
                            let c = C::from_u8(b);
                            *d = if to_lowcase { c.lower(tl, wc) } else { c.upper(tl, wc) };
                        }
                    }
                });
            }};
        }

        // The number tail shared by `Number` and `%s`: sign, padding to `digits`, the digits.
        macro_rules! emit_number {
            ($buf:ident, $bp:expr, $negative:expr, $digits:expr) => {{
                let mut bp: usize = $bp;
                let negative: bool = $negative;
                let digits: i32 = $digits;
                if negative {
                    bp -= 1;
                    $buf[bp] = b'-';
                }
                if pad != b'-' {
                    let padding = digits - ($buf.len() - bp) as i32;
                    if padding > 0 {
                        if pad == b'_' {
                            if (padding as usize) >= room!() {
                                return 0;
                            }
                            if let Some(o) = out.take() {
                                let (head, rest) = o.split_at_mut(padding as usize);
                                pad_units(head, b' ');
                                out = Some(rest);
                            }
                            i += padding as usize;
                            width = if width > padding { width - padding } else { 0 };
                        } else {
                            if (digits as usize) >= room!() {
                                return 0;
                            }
                            // (the room check covers the sign and the padding: digits > padding)
                            if negative {
                                bp += 1;
                                if let Some(o) = out.take() {
                                    let (head, rest) = o.split_at_mut(1);
                                    head[0] = C::from_u8(b'-');
                                    out = Some(rest);
                                }
                                i += 1;
                            }
                            if let Some(o) = out.take() {
                                let (head, rest) = o.split_at_mut(padding as usize);
                                pad_units(head, b'0');
                                out = Some(rest);
                            }
                            i += padding as usize;
                            width = 0;
                        }
                    }
                }
                cpyb!(&$buf[bp..]);
            }};
        }

        if fz.cur().asc() != b'%' {
            let c = fz.cur();
            let mut t = fz;
            t.bump();
            if t.at_end() || t.cur().asc() == b'%' {
                // one literal character (the separators of most formats): stored as it is, without the run's slicing
                // and copy (about 10 instructions per separator, FIXLIST #89)
                if 1 >= room!() {
                    return 0;
                }
                // (the room check left at least two units: the split always succeeds)
                if let Some(o) = out.take()
                    && let Some((h, rest)) = o.split_first_mut()
                {
                    *h = c;
                    out = Some(rest);
                }
                i += 1;
                fz = t;
                continue;
            }
            // a run of literal characters in one step
            let start = fz.pos();
            while !t.at_end() && t.cur().asc() != b'%' {
                t.bump();
            }
            if t.pos() - start >= room!() {
                // does not fit: character by character, so the partial output is exactly the same
                if 1 >= room!() {
                    return 0;
                }
                t = fz;
                t.bump();
            }
            let run = &t.scanned()[start..];
            // (width is -1 here: no padding) one room check, one copy
            if let Some(o) = out.take() {
                let (head, rest) = o.split_at_mut(run.len());
                C::copy(head, run);
                out = Some(rest);
            }
            i += run.len();
            fz = t;
            continue;
        }
        // flags
        loop {
            fz.bump();
            match fz.cur().asc() {
                b'_' | b'-' | b'0' => {
                    pad = fz.cur().asc();
                    continue;
                }
                b'^' => {
                    to_uppcase = true;
                    continue;
                }
                b'#' => {
                    change_case = true;
                    continue;
                }
                _ => break,
            }
        }
        // width
        if fz.cur().asc().is_ascii_digit() {
            width = 0;
            while fz.cur().asc().is_ascii_digit() {
                let d = (fz.cur().asc() - b'0') as i32;
                if width > i32::MAX / 10 || (width == i32::MAX / 10 && d > i32::MAX % 10) {
                    width = i32::MAX;
                } else {
                    width = width * 10 + d;
                }
                fz.bump();
            }
        }
        // modifier
        let modifier = if fz.cur().asc() == b'E' || fz.cur().asc() == b'O' {
            let m = fz.cur().asc();
            fz.bump();
            m
        } else {
            0
        };
        let format_char = fz.cur().asc();
        // The conversion picks its tail (a number, a sub-format, the conversion as written), or writes its text itself and
        // gives `Switch` (done). Two steps in a row, not a loop: as a loop, the state it carried was copied into new stack
        // slots on every conversion.
        let next: Next<C> = 'sw: {
            {
                {
                    macro_rules! number {
                        ($d:expr, $v:expr) => {{
                            let d: i32 = $d;
                            break 'sw Next::Number(d, $v, false);
                        }};
                    }
                    macro_rules! number_sp {
                        ($d:expr, $v:expr) => {{
                            let d: i32 = $d;
                            break 'sw Next::Number(d, $v, true);
                        }};
                    }
                    macro_rules! bad {
                        () => {{
                            break 'sw Next::Bad;
                        }};
                    }
                    macro_rules! text {
                        ($it:expr) => {
                            C::text(tl, $it, &mut tmp)
                        };
                    }
                    macro_rules! sub {
                        ($it:expr) => {
                            C::subfmt(tl, $it, &mut tmp)
                        };
                    }
                    match format_char {
                        b'%' => {
                            if modifier != 0 {
                                bad!();
                            }
                            add!(1, |q| q[0] = C::from_u8(b'%'));
                        }
                        b'a' => {
                            if modifier != 0 {
                                bad!();
                            }
                            if change_case {
                                to_uppcase = true;
                                to_lowcase = false;
                            }
                            // (the field read once: each `rv` is a volatile load and a range check of its own)
                            let wd = rv(&tp.tm_wday);
                            let t = if (0..=6).contains(&wd) {
                                text!(It::AbDay(wd as usize))
                            } else if C::WIDE {
                                garbage!();
                                break 'sw Next::Switch;
                            } else {
                                text!(It::Lit(b"?\0"))
                            };
                            cpy!(t.get(&tmp));
                        }
                        b'A' => {
                            if modifier != 0 {
                                bad!();
                            }
                            if change_case {
                                to_uppcase = true;
                                to_lowcase = false;
                            }
                            // (the field read once: each `rv` is a volatile load and a range check of its own)
                            let wd = rv(&tp.tm_wday);
                            let t = if (0..=6).contains(&wd) {
                                text!(It::Day(wd as usize))
                            } else if C::WIDE {
                                garbage!();
                                break 'sw Next::Switch;
                            } else {
                                text!(It::Lit(b"?\0"))
                            };
                            cpy!(t.get(&tmp));
                        }
                        b'b' | b'h' => {
                            if change_case {
                                to_uppcase = true;
                                to_lowcase = false;
                            }
                            if modifier == b'E' {
                                bad!();
                            }
                            let mon = rv(&tp.tm_mon);
                            let t = if !(0..=11).contains(&mon) {
                                if C::WIDE {
                                    garbage!();
                                    break 'sw Next::Switch;
                                }
                                text!(It::Lit(b"?\0"))
                            } else if modifier == b'O' {
                                text!(It::AbAltMon(mon as usize))
                            } else {
                                text!(It::AbMon(mon as usize))
                            };
                            cpy!(t.get(&tmp));
                        }
                        b'B' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            if change_case {
                                to_uppcase = true;
                                to_lowcase = false;
                            }
                            let mon = rv(&tp.tm_mon);
                            let t = if !(0..=11).contains(&mon) {
                                if C::WIDE {
                                    garbage!();
                                    break 'sw Next::Switch;
                                }
                                text!(It::Lit(b"?\0"))
                            } else if modifier == b'O' {
                                text!(It::AltMon(mon as usize))
                            } else {
                                text!(It::Mon(mon as usize))
                            };
                            cpy!(t.get(&tmp));
                        }
                        b'c' => {
                            if modifier == b'O' {
                                bad!();
                            }
                            let e = text!(It::EraDTFmt);
                            let sub = if modifier == b'E' && e.len() != 0 { sub!(It::EraDTFmt) } else { sub!(It::DTFmt) };
                            break 'sw Next::Sub(sub);
                        }
                        b'C' => {
                            if modifier == b'E'
                                && let Some(era) = tl.era_for(rv(&tp.tm_year), rv(&tp.tm_mon), rv(&tp.tm_mday))
                            {
                                let t = text!(It::EraName(&era));
                                cpy!(t.get(&tmp));
                                break 'sw Next::Switch;
                            }
                            number!(1, tm_number(b'C', tp));
                        }
                        b'x' => {
                            if modifier == b'O' {
                                bad!();
                            }
                            let e = text!(It::EraDFmt);
                            let sub = if modifier == b'E' && e.len() != 0 { sub!(It::EraDFmt) } else { sub!(It::DFmt) };
                            break 'sw Next::Sub(sub);
                        }
                        b'D' => {
                            if modifier != 0 {
                                bad!();
                            }
                            break 'sw Next::Sub(sub!(It::Lit(b"%m/%d/%y\0")));
                        }
                        b'd' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(2, rv(&tp.tm_mday));
                        }
                        b'e' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number_sp!(2, rv(&tp.tm_mday));
                        }
                        b'F' => {
                            if modifier != 0 {
                                bad!();
                            }
                            break 'sw Next::Sub(sub!(It::Lit(b"%Y-%m-%d\0")));
                        }
                        b'H' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(2, rv(&tp.tm_hour));
                        }
                        b'I' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(2, hour12!());
                        }
                        b'k' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number_sp!(2, rv(&tp.tm_hour));
                        }
                        b'l' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number_sp!(2, hour12!());
                        }
                        b'j' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(3, 1i32.wrapping_add(rv(&tp.tm_yday)));
                        }
                        b'M' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(2, rv(&tp.tm_min));
                        }
                        b'm' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(2, rv(&tp.tm_mon).wrapping_add(1));
                        }
                        b'n' => {
                            add!(1, |q| q[0] = C::from_u8(b'\n'));
                        }
                        b'P' | b'p' => {
                            if format_char == b'P' {
                                to_lowcase = true;
                            }
                            if change_case {
                                to_uppcase = false;
                                to_lowcase = true;
                            }
                            let t = text!(It::AmPm(rv(&tp.tm_hour) > 11));
                            cpy!(t.get(&tmp));
                        }
                        b'R' => {
                            break 'sw Next::Sub(sub!(It::Lit(b"%H:%M\0")));
                        }
                        b'r' => {
                            let e = text!(It::TFmtAmpm);
                            break 'sw Next::Sub(if e.len() == 0 { sub!(It::Lit(timeloc::C_T_FMT_AMPM)) } else { sub!(It::TFmtAmpm) });
                        }
                        b'S' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(2, rv(&tp.tm_sec));
                        }
                        b's' => {
                            let mut ltm = *tp;
                            let t = calendar::mktime_tm(&mut ltm);
                            let negative = t < 0;
                            let mut tt = t;
                            let mut bp = buf.len();
                            loop {
                                let mut d = (tt % 10) as i32;
                                tt /= 10;
                                if negative {
                                    d = -d;
                                }
                                bp -= 1;
                                buf[bp] = b'0' + d as u8;
                                if tt == 0 {
                                    break;
                                }
                            }
                            emit_number!(buf, bp, negative, 1);
                        }
                        b'X' => {
                            if modifier == b'O' {
                                bad!();
                            }
                            let e = text!(It::EraTFmt);
                            let sub = if modifier == b'E' && e.len() != 0 { sub!(It::EraTFmt) } else { sub!(It::TFmt) };
                            break 'sw Next::Sub(sub);
                        }
                        b'T' => {
                            break 'sw Next::Sub(sub!(It::Lit(b"%H:%M:%S\0")));
                        }
                        b't' => {
                            add!(1, |q| q[0] = C::from_u8(b'\t'));
                        }
                        b'u' => {
                            number!(1, tm_number(b'u', tp));
                        }
                        b'U' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(2, tm_number(b'U', tp));
                        }
                        b'V' | b'g' | b'G' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            match format_char {
                                b'g' => number!(2, tm_number(b'g', tp)),
                                b'G' => number!(1, tm_number(b'G', tp)),
                                _ => number!(2, tm_number(b'V', tp)),
                            }
                        }
                        b'W' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(2, tm_number(b'W', tp));
                        }
                        b'w' => {
                            if modifier == b'E' {
                                bad!();
                            }
                            number!(1, rv(&tp.tm_wday));
                        }
                        b'Y' => {
                            if modifier == b'E'
                                && let Some(era) = tl.era_for(rv(&tp.tm_year), rv(&tp.tm_mon), rv(&tp.tm_mday))
                            {
                                if pad != 0 {
                                    yr_spec = pad;
                                }
                                break 'sw Next::Sub(sub!(It::EraFormat(&era)));
                            }
                            if modifier == b'O' {
                                bad!();
                            }
                            number!(1, rv(&tp.tm_year).wrapping_add(1900));
                        }
                        b'y' => {
                            if modifier == b'E'
                                && let Some(era) = tl.era_for(rv(&tp.tm_year), rv(&tp.tm_mon), rv(&tp.tm_mday))
                            {
                                let delta = rv(&tp.tm_year).wrapping_sub(era.start_date[0]);
                                if yr_spec != 0 {
                                    pad = yr_spec;
                                }
                                number!(2, era.offset.wrapping_add(delta.wrapping_mul(era.absolute_direction)));
                            }
                            number!(2, tm_number(b'y', tp));
                        }
                        b'Z' => {
                            if change_case && !C::WIDE {
                                to_uppcase = false;
                                to_lowcase = true;
                            }
                            // SAFETY: `tm_zone` is NULL or points to a C string (the contract of `struct tm`: ours point to
                            // interned names that live for ever, a program's to its own strings); only read here, for %Z.
                            let mut zb: Option<&[u8]> = unsafe { ffi::cstr(zone) }.map(|z| z.to_bytes());
                            if zb.is_none_or(|z| z.is_empty()) && rv(&tp.tm_isdst) >= 0 {
                                if !*tzset_called {
                                    tz::tzset_now();
                                    *tzset_called = true;
                                }
                                zone = if rv(&tp.tm_isdst) <= 1 { tz::tzname_ptr(rv(&tp.tm_isdst) as usize) } else { c"?".as_ptr() };
                                // SAFETY: a `tzname` entry is NULL or a C string that lives for ever (see `tz::names`).
                                zb = unsafe { ffi::cstr(zone) }.map(|z| z.to_bytes());
                            }
                            let zt = zb.unwrap_or(b"");
                            if !C::WIDE {
                                cpyb!(zt);
                            } else if let Some(o) = out.take_if(|o| zt.len() < o.len() && (pad == b'-' || width <= zt.len() as i32)) {
                                // the common case in line: a name that fits without padding (glibc's wide %Z has no case
                                // flags and pads nothing for `-`), widened while it is ASCII (the same in every locale
                                // charset), then the 0 glibc's conversion leaves after an unpadded name (the room check left
                                // that unit). A byte above 0x7f hands the name to `wide_zone`, which converts it from the
                                // start: what was written so far is the same ASCII prefix it writes again.
                                let n = zt.len();
                                let mut ascii = true;
                                for (d, &b) in o[..n].iter_mut().zip(zt) {
                                    if b >= 0x80 {
                                        ascii = false;
                                        break;
                                    }
                                    *d = C::from_u8(b);
                                }
                                if ascii {
                                    let rest = &mut o[n..];
                                    rest[0] = C::from_u8(0);
                                    i += n;
                                    out = Some(rest);
                                } else {
                                    out = Some(o);
                                    if wide_zone(&mut out, &mut i, maxsize, zt, pad, width, wc).is_none() {
                                        return 0;
                                    }
                                }
                            } else if wide_zone(&mut out, &mut i, maxsize, zt, pad, width, wc).is_none() {
                                return 0;
                            }
                        }
                        b'z' => {
                            if rv(&tp.tm_isdst) < 0 {
                                // nothing
                            } else {
                                // (glibc's `int diff = tp->tm_gmtoff`, negated when negative: for INT_MIN its compiled code
                                // divides the negation as an unsigned number, giving -59652314 where a signed one gives
                                // --59652314)
                                let mut diff = rv(&tp.tm_gmtoff) as i32;
                                if diff < 0 {
                                    add!(1, |q| q[0] = C::from_u8(b'-'));
                                    diff = diff.wrapping_neg();
                                } else {
                                    add!(1, |q| q[0] = C::from_u8(b'+'));
                                }
                                let diff = (diff as u32 / 60) as i32;
                                number!(4, (diff / 60) * 100 + diff % 60);
                            }
                        }
                        0 => {
                            bad!();
                        }
                        _ => {
                            bad!();
                        }
                    }
                    Next::Switch
                }
            }
        };
        'tail: {
            match next {
                Next::Switch => {}
                Next::Number(digits, number_value, spacepad) => {
                    // the width is applied here, not where the conversion is chosen (it was computed for every conversion)
                    let digits = if digits > width { digits } else { width };
                    if spacepad && pad != b'0' && pad != b'-' {
                        pad = b'_';
                    }
                    // `O` with a non-negative number: the locale's alternative digits, if it has some
                    if modifier == b'O' && number_value >= 0 {
                        let t = C::text(tl, It::AltDigit(number_value as u32), &mut tmp);
                        if t.len() != 0 {
                            cpy!(t.get(&tmp));
                            break 'tail;
                        }
                    }
                    let mut bp = buf.len();
                    let negative = number_value < 0;
                    let mut u = number_value as u32;
                    if negative {
                        u = u.wrapping_neg();
                    }
                    // two digits at a time from a table
                    // (each pair one 2-byte store: the copy below reads 2 or 4 bytes at once, and a load that spans two
                    // stores waits for them to retire)
                    while u >= 100 {
                        let r = (u % 100) as usize;
                        u /= 100;
                        bp -= 2;
                        buf[bp..bp + 2].copy_from_slice(&DIGIT_PAIRS[2 * r..2 * r + 2]);
                    }
                    if u >= 10 {
                        bp -= 2;
                        buf[bp..bp + 2].copy_from_slice(&DIGIT_PAIRS[2 * u as usize..2 * u as usize + 2]);
                    } else {
                        bp -= 1;
                        buf[bp] = u as u8 + b'0';
                    }
                    emit_number!(buf, bp, negative, digits);
                    break 'tail;
                }
                Next::Sub(subt) => {
                    // (the output and the count go in and come back by value: as `&mut` arguments they would live in
                    // memory for the whole engine)
                    match sub_format(subt, &tmp, out.take(), i, maxsize, width, pad, to_uppcase, tp, tzset_called, tl, wc, yr_spec) {
                        Some((o, n)) => {
                            out = o;
                            i = n;
                        }
                        None => return 0,
                    }
                    break 'tail;
                }
                Next::Bad => {
                    // the conversion as written: from its `%` to the conversion character (to the end of the format if
                    // that is where it stops)
                    let mut t = fz;
                    t.bump();
                    let seen = t.scanned();
                    let start = seen.iter().rposition(|&c| c.asc() == b'%').unwrap_or(0);
                    cpy!(&seen[start..]);
                    break 'tail;
                }
            }
        }
        fz.bump();
    }
    if let Some(o) = out
        && maxsize != 0
        && let Some(end) = o.first_mut()
    {
        *end = C::from_u8(0);
    }
    i
}

/// `%Z` of `wcsftime`, as glibc 2.43 does it: the zone name `z` (its bytes, without the NUL) is converted with the locale's
/// `mbsrtowcs` straight into the output, before the room check (so a call that fails here leaves the converted part, and
/// its 0 if it fitted, in the buffer); a conversion error fails (errno EILSEQ from the conversion), a result that does not
/// fit fails with errno ERANGE; then the name is padded on the left to `width` (with zeros for the `0` flag; no padding
/// for `-`). No case flags: glibc's wide `%Z` ignores `^` and `#`. Advances `out` and the count `i`; None if the call
/// fails.
#[inline(never)]
fn wide_zone<C: Ch>(out: &mut Option<&mut [C]>, i: &mut usize, maxsize: usize, z: &[u8], pad: u8, width: i32, wc: Wc) -> Option<()> {
    let w = if pad == b'-' || width < 0 { 0 } else { width as usize };
    let room = match out {
        Some(o) => o.len(),
        None => maxsize.wrapping_sub(*i),
    };
    let out_w = out.as_deref_mut().and_then(C::as_wide);
    let len = if z.is_ascii() {
        // ASCII is the same in every locale charset (`mbs` would give the same result): the name, then its 0 if it fits
        match out_w {
            Some(o) => {
                let k = z.len().min(o.len());
                for (d, &b) in o.iter_mut().zip(&z[..k]) {
                    *d = u32::from(b);
                }
                if let Some(d) = o.get_mut(k)
                    && k == z.len()
                {
                    *d = 0;
                }
                k
            }
            None => z.len(),
        }
    } else {
        (wc.ops.mbs)(z, out_w, wc.loc)?
    };
    let incr = len.max(w);
    if incr >= room {
        rusty_libc_core::errno::set(ERANGE);
        return None;
    }
    if let Some(o) = out.take() {
        if len < w {
            let delta = w - len;
            o.copy_within(0..len, delta);
            fill(&mut o[..delta], if pad == b'0' { b'0' } else { b' ' });
        }
        *out = Some(&mut o[incr..]);
    }
    *i += incr;
    Some(())
}

/// The `Next::Sub` step of the engine (`%c`, `%T` ...), out of line so that its scratch arrays stay out of the engine's
/// frame: expand the sub-format, pad it to `width` and append it to `out` (the output not written yet; `i` units were
/// written or counted before it). Returns the output still free and the new count; None if it does not fit (the engine
/// then returns 0).
#[inline(never)]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn sub_format<'o, C: Ch>(subt: SubF<C>, tmp: &[C; TMP], mut out: Option<&'o mut [C]>, i: usize, maxsize: usize, width: i32, pad: u8, to_uppcase: bool, tp: &Tm, tzset_called: &mut bool, tl: &TimeLoc, wc: Wc, yr_spec: u8) -> Option<(Option<&'o mut [C]>, usize)> {
    // the sub-format as a NUL-terminated string: in place, or a copy of a locale's item
    let mut copy = NulCopy::new();
    let subfmt: ZStr<'_, C> = match subt {
        SubF::Z(z) => z,
        // (`text` put the NUL at `tmp[n]`, so this cursor always exists)
        SubF::Tmp(n) => match ZStr::from_nul_terminated(&tmp[..=n]) {
            Some(z) => z,
            None => return Some((out, i)),
        },
        // (no copy: a format longer than 127 units and no memory for it; nothing is written)
        SubF::S(sl) => copy.z(sl)?,
    };
    // Most common case: no width, the C locale's sub-formats (%T, %D, %c ...: at most 67 units even for absurd field
    // values, 11 per number) and more room than any of them needs: written in place, with no copy (copied from the
    // scratch array below, the text was read back before its stores had retired, and the wide array cost 256 bytes of
    // zeroing: wcsftime 1.04x its time before U2, FIXLIST #89). Same result as below: the expansion always fits, so the
    // call cannot stop half-way (glibc writes nothing when the room check fails).
    // (not for glibc's wide "?" names: the expansion then does not fit, and glibc writes none of it)
    if width <= 0
        && tl.is_c()
        && !(C::WIDE && wide_name_garbage(tp))
        && let Some(o) = out.take()
    {
        if o.len() > 128 {
            let room = o.len();
            let n = strftime_internal(Some(&mut o[..]), room, subfmt, tp, tzset_called, tl, wc, yr_spec);
            if to_uppcase {
                upcase(&mut o[..n], tl, wc);
            }
            return Some((Some(&mut o[n..]), i + n));
        }
        out = Some(o);
    }
    // Common case: the expansion fits a small scratch buffer, so it is produced once and copied (the length pass below
    // runs the whole format a second time). Same result: the text of a sub-format does not depend on where it is written.
    // (64 units: the C locale's longest expansion, %c, is 24; a longer one takes the length pass)
    let mut scratch = [C::from_u8(0); 64];
    let mut tz2 = *tzset_called;
    let r = strftime_internal(Some(&mut scratch), 64, subfmt, tp, &mut tz2, tl, wc, yr_spec);
    let quick = r != 0;
    let n = if quick {
        *tzset_called = tz2;
        r
    } else {
        let mut tz2 = *tzset_called;
        let len = strftime_internal(None, usize::MAX, subfmt, tp, &mut tz2, tl, wc, yr_spec);
        *tzset_called = tz2;
        // (a count with glibc's wide "?" names in it is at least i32::MAX: it fits no buffer, and adds as it is when
        // only counting, the width being smaller)
        if C::WIDE && len >= i32::MAX as usize {
            return if out.is_some() { None } else { Some((None, i + len)) };
        }
        len
    };
    // (a count with glibc's wide "?" names in it is at least i32::MAX: it fits no buffer, and adds as it is when only
    // counting, the width being smaller)
    // the engine's `add!`: room check, padding to `width`, the text
    let nn = n as i32;
    let delta = width - nn;
    let incr = nn + if delta > 0 { delta } else { 0 };
    match out.take() {
        Some(o) => {
            if (incr as usize) >= o.len() {
                return None;
            }
            let mut at = 0;
            if delta > 0 {
                fill(&mut o[..delta as usize], if pad == b'0' { b'0' } else { b' ' });
                at = delta as usize;
            }
            let q = &mut o[at..];
            if quick {
                // (the inner call of the length-pass form also leaves its NUL after the text: the room check guarantees
                // the unit exists)
                C::copy(&mut q[..n], &scratch[..n]);
                q[n] = C::from_u8(0);
            } else {
                // (the rest of the output: the room check left space for the text and its NUL)
                // (it writes the `n` units the length pass counted; only glibc's wide "?" names, counted but never
                // written, make it fail, in a buffer said to be larger than 2^31 characters)
                let room = q.len();
                let _ = strftime_internal(Some(&mut q[..]), room, subfmt, tp, tzset_called, tl, wc, yr_spec);
            }
            // (glibc also upper-cases the padding, blanks or zeros, which changes nothing)
            if to_uppcase {
                upcase(&mut q[..n], tl, wc);
            }
            out = Some(&mut o[incr as usize..]);
        }
        None => {
            if (incr as usize) >= maxsize.wrapping_sub(i) {
                return None;
            }
        }
    }
    Some((out, i + incr as usize))
}

/// The output buffer of a C call: None for NULL (count only), else `maxsize` units at `s` (clamped to what a slice can
/// span; an output that long cannot be produced anyway). Returns the buffer and the capacity to use.
///
/// # Safety
/// `s` is NULL or valid for writes of `maxsize` units that nothing else accesses during the call (strftime's contract).
unsafe fn out_buf<'a, C>(s: *mut C, maxsize: usize) -> (Option<&'a mut [C]>, usize) {
    if s.is_null() {
        return (None, maxsize);
    }
    let cap = maxsize.min(isize::MAX as usize / size_of::<C>());
    // SAFETY: forwarded contract (`cap` <= `maxsize`).
    (Some(unsafe { ffi::slice_mut(s, cap) }), cap)
}

/// The engine behind `strftime` and `strftime_l`.
///
/// # Safety
/// As `strftime`.
unsafe fn strftime_c(s: *mut c_char, maxsize: usize, format: *const c_char, tp: *const Tm, tl: &TimeLoc) -> usize {
    // SAFETY: `format` is a C string (the C contract; a NULL faults on the first read, as in glibc).
    let format = unsafe { ZStr::new(format.cast::<u8>()) };
    // SAFETY: `tp` points to a valid struct tm (the C contract; a NULL faults, as in glibc).
    let tm = unsafe { sys::arg(tp) };
    // SAFETY: `s` is NULL or has room for `maxsize` bytes (the C contract).
    let (out, cap) = unsafe { out_buf(s.cast::<u8>(), maxsize) };
    let mut tzset_called = false;
    strftime_internal::<u8>(out, cap, format, tm, &mut tzset_called, tl, NARROW, 0)
}

/// `size_t strftime(char *s, size_t max, const char *format, const struct tm *tp)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strftime(s: *mut c_char, maxsize: usize, format: *const c_char, tp: *const Tm) -> usize {
    // SAFETY: the caller's contract is strftime's.
    unsafe { strftime_c(s, maxsize, format, tp, &TimeLoc::current()) }
}

/// `size_t strftime_l(...)`: the names and formats of `loc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strftime_l(s: *mut c_char, maxsize: usize, format: *const c_char, tp: *const Tm, loc: LocaleT) -> usize {
    // SAFETY: `loc` is a locale_t or LC_GLOBAL_LOCALE (the caller's contract).
    let tl = unsafe { TimeLoc::of_locale(loc as usize) };
    // SAFETY: the caller's contract is strftime's.
    unsafe { strftime_c(s, maxsize, format, tp, &tl) }
}

/// `wcsftime` and `wcsftime_l`, called by rusty-libc-wchar with its case mapping: the same engine as
/// `strftime` over wide characters, with the wide LC_TIME items. Counts and widths are in wide
/// characters.
///
/// # Safety
/// `s` must be valid for `maxsize` wide characters, `format` NUL-terminated, `tp` valid, `loc` 0 or a locale_t.
pub unsafe fn wcsftime_with(s: *mut u32, maxsize: usize, format: *const u32, tp: *const Tm, loc: usize, ops: &'static WcOps) -> usize {
    // SAFETY: `format` is a 0-terminated wide string (the contract), 4-aligned, not written during the call.
    let format = unsafe { ZStr::new(format) };
    // SAFETY: `tp` points to a valid struct tm (the contract).
    let tm = unsafe { sys::arg(tp) };
    // SAFETY: `s` is NULL or has room for `maxsize` wide characters (the contract).
    let (out, cap) = unsafe { out_buf(s, maxsize) };
    let mut tzset_called = false;
    // SAFETY: `loc` is 0 or a locale_t (the contract).
    let tl = if loc == 0 { TimeLoc::current() } else { unsafe { TimeLoc::of_locale(loc) } };
    // SAFETY: as above.
    let loc = unsafe { Loc::from_raw(loc) };
    strftime_internal::<u32>(out, cap, format, tm, &mut tzset_called, &tl, Wc { ops, loc }, 0)
}

/// Format `tm` with `format` into a byte buffer; the Rust API for callers without a C buffer (the result is
/// NUL-terminated in `out`). `None` if it does not fit (or the result is empty and `out` was too small).
pub fn format(out: &mut [u8], format: &[u8], tm: &Tm) -> Option<usize> {
    // the format ends at its first NUL, like the C string it stands for
    if format.len() >= 256 || out.is_empty() {
        return None;
    }
    let fmt = &format[..format.iter().position(|&c| c == 0).unwrap_or(format.len())];
    let mut tzset_called = false;
    let cap = out.len();
    // (shorter than 256 bytes: the NUL-terminated copy is on the stack)
    let n = with_nul(fmt, |z| strftime_internal::<u8>(Some(out), cap, z, tm, &mut tzset_called, &TimeLoc::current(), NARROW, 0))?;
    if n == 0 && !format.is_empty() { None } else { Some(n) }
}

// ------------------------------------------------------------------ strptime

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decided {
    Not,
    Loc,
    Raw,
}

/// strptime's parse state, handed to nested calls (and back on their success). The flags are bits of one integer: as 11
/// `bool` fields the compiler kept them packed in a vector register and rebuilt it with about a dozen instructions (a
/// spill and byte reloads) for every flag set (FIXLIST #89).
#[derive(Clone, Copy)]
struct PState {
    /// `PState::HAVE_I` ... `PState::WANT_XDAY`
    flags: u16,
    decided: Decided,
    week_no: i8,
    century: i8,
    era_cnt: i32,
}

impl PState {
    const HAVE_I: u16 = 1 << 0;
    const HAVE_WDAY: u16 = 1 << 1;
    const HAVE_YDAY: u16 = 1 << 2;
    const HAVE_MON: u16 = 1 << 3;
    const HAVE_MDAY: u16 = 1 << 4;
    const HAVE_UWEEK: u16 = 1 << 5;
    const HAVE_WWEEK: u16 = 1 << 6;
    const IS_PM: u16 = 1 << 7;
    const WANT_CENTURY: u16 = 1 << 8;
    const WANT_ERA: u16 = 1 << 9;
    const WANT_XDAY: u16 = 1 << 10;

    #[inline(always)]
    fn has(&self, f: u16) -> bool {
        self.flags & f != 0
    }
    #[inline(always)]
    fn set(&mut self, f: u16) {
        self.flags |= f;
    }
    #[inline(always)]
    fn clear(&mut self, f: u16) {
        self.flags &= !f;
    }
}

const FLAT_MON_YDAY: [i32; 26] = [
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365, //
    0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366,
];

/// `__mon_yday[leap][m]` as the C array access reads it, past the row ends too (the table is
/// two rows in a row; before the start and after the end glibc reads whatever is there: 0 here).
fn mon_yday(leap: bool, m: isize) -> i32 {
    let f = leap as isize * 13 + m;
    if (0..26).contains(&f) {
        FLAT_MON_YDAY[f as usize]
    } else if f < 0 {
        0
    } else {
        0x7fff // glibc's loop was observed to stop right after the table
    }
}

fn isspace_c(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn day_of_the_week(tm: &mut Tm) {
    let corr_year = 1900i32.wrapping_add(tm.tm_year).wrapping_sub((tm.tm_mon < 2) as i32);
    let c4 = corr_year / 4;
    let wday = (-473i32)
        .wrapping_add(365i32.wrapping_mul(tm.tm_year.wrapping_sub(70)))
        .wrapping_add(c4)
        .wrapping_sub(c4 / 25)
        .wrapping_add((c4 % 25 < 0) as i32)
        .wrapping_add((c4 / 25) / 4)
        .wrapping_add(mon_yday(false, tm.tm_mon as isize))
        .wrapping_add(tm.tm_mday)
        .wrapping_sub(1);
    tm.tm_wday = ((wday % 7) + 7) % 7;
}

fn day_of_the_year(tm: &mut Tm) {
    tm.tm_yday = mon_yday(isleap(1900i32.wrapping_add(tm.tm_year)), tm.tm_mon as isize).wrapping_add(tm.tm_mday.wrapping_sub(1));
}

/// Case-insensitive prefix match of `name` at the cursor (past the end of the input every byte reads as its NUL);
/// moves `*rp` past it on success.
#[inline(always)]
fn match_string(name: &[u8], rp: &mut ZStr<'_, u8>) -> bool {
    // like strncasecmp: bytes are equal after the case mapping of the locale in force
    let ct = if rusty_libc_core::locale::ctype_special() { rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) } else { None };
    let mut t = *rp;
    for &c in name {
        let x = t.cur();
        if x != c && rusty_libc_core::locale::tolower_in(ct, i32::from(x)) != rusty_libc_core::locale::tolower_in(ct, i32::from(c)) {
            return false;
        }
        // (a match of the NUL can only be a NUL in `name`, which names do not hold: the cursor then stays on it, and every
        // later byte reads as NUL, as past the end of the C string)
        t.bump();
    }
    *rp = t;
    true
}

/// glibc's `__strptime_internal` on the input at the cursor `rp` with the format at the cursor `fz` (both NUL-terminated
/// strings, read only as far as the conversion goes, as the C pointer walk did). Returns the cursor at the first input
/// byte not consumed. A `nested` call (a state given) works on the caller's copies of the state and `Tm` and hands the
/// state back on success.
#[allow(clippy::manual_range_contains, clippy::absurd_extreme_comparisons, unused_comparisons)]
fn strptime_internal<'a>(mut rp: ZStr<'a, u8>, mut fz: ZStr<'_, u8>, tmp: &mut Tm, state: Option<&mut PState>, tl: &TimeLoc) -> Option<ZStr<'a, u8>> {
    {
        let mut s = match &state {
            Some(st) => **st,
            None => PState {
                flags: 0,
                decided: Decided::Not,
                week_no: 0,
                century: -1,
                era_cnt: -1,
            },
        };
        // (a nested call works on the caller's copy of its `Tm`, which the caller keeps only on success: glibc's own
        // second copy inside the nested call is not needed)
        let tm: &mut Tm = tmp;
        let mut val: usize;

        macro_rules! fail {
            () => {
                return None
            };
        }
        macro_rules! get_number {
            ($from:expr, $to:expr, $n:expr) => {{
                let mut n: i32 = $n;
                val = 0;
                while isspace_c(rp.cur()) {
                    rp.bump();
                }
                if rp.cur() < b'0' || rp.cur() > b'9' {
                    fail!();
                }
                loop {
                    val = val.wrapping_mul(10).wrapping_add((rp.cur() - b'0') as usize);
                    rp.bump();
                    n -= 1;
                    if n <= 0 || val * 10 > $to || !rp.cur().is_ascii_digit() {
                        break;
                    }
                }
                if val < $from || val > $to {
                    fail!();
                }
            }};
        }
        // The locale's alternative digits: tried first unless the input is already known to be in the
        // C locale's form; if there are none, the first use settles `decided` to `Loc` and the plain
        // number is read, a later one (in the `Loc` state) finds nothing and fails, as glibc does.
        macro_rules! get_alt_number {
            ($from:expr, $to:expr, $n:expr) => {{
                if s.decided != Decided::Raw {
                    let v = tl.parse_alt_digit(&mut rp);
                    if v == -1 && s.decided != Decided::Loc {
                        s.decided = Decided::Loc;
                        get_number!($from, $to, $n);
                    } else {
                        val = v as isize as usize;
                        if val < $from || val > $to {
                            fail!();
                        }
                    }
                } else {
                    get_number!($from, $to, $n);
                }
            }};
        }
                macro_rules! recursive {
            ($f:expr) => {{
                let nf: Fmt = $f;
                if nf.is_empty() {
                    false
                } else {
                    let mut s2 = s;
                    let mut tm2 = *tm;
                    let r = match nf {
                        Fmt::Z(z) => strptime_internal(rp, z, &mut tm2, Some(&mut s2), tl),
                        // (a locale's format: run on a NUL-terminated copy; None also if that copy cannot be made)
                        Fmt::S(f) => with_nul(f, |z| strptime_internal(rp, z, &mut tm2, Some(&mut s2), tl)).flatten(),
                    };
                    if let Some(r) = r {
                        rp = r;
                        s = s2;
                        *tm = tm2;
                        true
                    } else {
                        false
                    }
                }
            }};
        }

        while !fz.at_end() {
            if isspace_c(fz.cur()) {
                while isspace_c(rp.cur()) {
                    rp.bump();
                }
                fz.bump();
                continue;
            }
            if fz.cur() != b'%' {
                if fz.cur() != rp.cur() {
                    fail!();
                }
                fz.bump();
                rp.bump();
                continue;
            }
            fz.bump();
            while matches!(fz.cur(), b'-' | b'_' | b'0' | b'^' | b'#') {
                fz.bump();
            }
            while fz.cur().is_ascii_digit() {
                fz.bump();
            }
            'start_over: loop {
                let rp_backup = rp;
                let _ = rp_backup;
                let conv = fz.cur();
                fz.bump();
                match conv {
                    b'%' => {
                        if rp.cur() != b'%' {
                            fail!();
                        }
                        rp.bump();
                    }
                    b'a' | b'A' => {
                        let c = TimeLoc::c();
                        let mut rp_longest: Option<ZStr<'a, u8>> = None;
                        let mut decided_longest = s.decided;
                        let mut cnt_longest: i32 = -1;
                        for cnt in 0..7usize {
                            let mut trp: ZStr<'a, u8>;
                            if s.decided != Decided::Raw {
                                for (name, cname) in [(tl.day(cnt), c.day(cnt)), (tl.abday(cnt), c.abday(cnt))] {
                                    trp = rp;
                                    if match_string(name, &mut trp) && rp_longest.is_none_or(|l| trp.pos() > l.pos()) {
                                        rp_longest = Some(trp);
                                        cnt_longest = cnt as i32;
                                        if s.decided == Decided::Not && name != cname {
                                            decided_longest = Decided::Loc;
                                        }
                                    }
                                }
                            }
                            if s.decided != Decided::Loc {
                                // glibc advances `rp` itself on the abbreviation test: kept
                                trp = rp;
                                let full = match_string(c.day(cnt), &mut trp) && rp_longest.is_none_or(|l| trp.pos() > l.pos());
                                let mut hit = full;
                                if !full {
                                    trp = rp;
                                    hit = match_string(c.abday(cnt), &mut rp) && rp_longest.is_none_or(|l| trp.pos() > l.pos());
                                }
                                if hit {
                                    rp_longest = Some(trp);
                                    cnt_longest = cnt as i32;
                                    decided_longest = Decided::Raw;
                                }
                            }
                        }
                        let longest = rp_longest?;
                        rp = longest;
                        s.decided = decided_longest;
                        tm.tm_wday = cnt_longest;
                        s.set(PState::HAVE_WDAY);
                    }
                    b'b' | b'B' | b'h' => {
                        let c = TimeLoc::c();
                        let mut rp_longest: Option<ZStr<'a, u8>> = None;
                        let mut decided_longest = s.decided;
                        let mut cnt_longest: i32 = -1;
                        for cnt in 0..12usize {
                            let mut trp: ZStr<'a, u8>;
                            if s.decided != Decided::Raw {
                                // (the abbreviated alternative name is compared with the C locale's full
                                // alternative name when deciding, as glibc does)
                                for (name, cname) in [(tl.mon(cnt), c.mon(cnt)), (tl.abmon(cnt), c.abmon(cnt)), (tl.altmon(cnt), c.altmon(cnt)), (tl.abaltmon(cnt), c.altmon(cnt))] {
                                    trp = rp;
                                    if match_string(name, &mut trp) && rp_longest.is_none_or(|l| trp.pos() > l.pos()) {
                                        rp_longest = Some(trp);
                                        cnt_longest = cnt as i32;
                                        if s.decided == Decided::Not && name != cname {
                                            decided_longest = Decided::Loc;
                                        }
                                    }
                                }
                            }
                            if s.decided != Decided::Loc {
                                for name in [c.mon(cnt), c.abmon(cnt), c.altmon(cnt), c.abaltmon(cnt)] {
                                    trp = rp;
                                    if match_string(name, &mut trp) && rp_longest.is_none_or(|l| trp.pos() > l.pos()) {
                                        rp_longest = Some(trp);
                                        cnt_longest = cnt as i32;
                                        decided_longest = Decided::Raw;
                                        break;
                                    }
                                }
                            }
                        }
                        let longest = rp_longest?;
                        rp = longest;
                        s.decided = decided_longest;
                        tm.tm_mon = cnt_longest;
                        s.set(PState::HAVE_MON);
                        s.set(PState::WANT_XDAY);
                    }
                    b'c' => {
                        if s.decided != Decided::Raw {
                            if !recursive!(tl.d_t_fmt_z()) {
                                if s.decided == Decided::Loc {
                                    fail!();
                                }
                                rp = rp_backup;
                            } else {
                                if s.decided == Decided::Not && tl.d_t_fmt() != no_nul(timeloc::C_D_T_FMT) {
                                    s.decided = Decided::Loc;
                                }
                                s.set(PState::WANT_XDAY);
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if !recursive!(Fmt::Z(ZStr::from(timeloc::C_D_T_FMT_Z))) {
                            fail!();
                        }
                        s.set(PState::WANT_XDAY);
                    }
                    b'C' => {
                        get_number!(0, 99, 2);
                        s.century = val as i8;
                        s.set(PState::WANT_XDAY);
                    }
                    b'd' | b'e' => {
                        get_number!(1, 31, 2);
                        tm.tm_mday = val as c_int;
                        s.set(PState::HAVE_MDAY);
                        s.set(PState::WANT_XDAY);
                    }
                    b'F' => {
                        if !recursive!(Fmt::Z(ZStr::from(c"%Y-%m-%d"))) {
                            fail!();
                        }
                        s.set(PState::WANT_XDAY);
                    }
                    b'x' | b'D' => {
                        if conv == b'x' && s.decided != Decided::Raw {
                            if !recursive!(tl.d_fmt_z()) {
                                if s.decided == Decided::Loc {
                                    fail!();
                                }
                                rp = rp_backup;
                            } else {
                                if s.decided == Decided::Not && tl.d_fmt() != no_nul(timeloc::C_D_FMT) {
                                    s.decided = Decided::Loc;
                                }
                                s.set(PState::WANT_XDAY);
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if !recursive!(Fmt::Z(ZStr::from(timeloc::C_D_FMT_Z))) {
                            fail!();
                        }
                        s.set(PState::WANT_XDAY);
                    }
                    b'k' | b'H' => {
                        get_number!(0, 23, 2);
                        tm.tm_hour = val as c_int;
                        s.clear(PState::HAVE_I);
                    }
                    b'l' | b'I' => {
                        get_number!(1, 12, 2);
                        tm.tm_hour = (val % 12) as c_int;
                        s.set(PState::HAVE_I);
                    }
                    b'j' => {
                        get_number!(1, 366, 3);
                        tm.tm_yday = val as c_int - 1;
                        s.set(PState::HAVE_YDAY);
                    }
                    b'm' => {
                        get_number!(1, 12, 2);
                        tm.tm_mon = val as c_int - 1;
                        s.set(PState::HAVE_MON);
                        s.set(PState::WANT_XDAY);
                    }
                    b'M' => {
                        get_number!(0, 59, 2);
                        tm.tm_min = val as c_int;
                    }
                    b'n' | b't' => {
                        while isspace_c(rp.cur()) {
                            rp.bump();
                        }
                    }
                    b'p' => {
                        if s.decided != Decided::Raw {
                            if match_string(tl.ampm(false), &mut rp) {
                                if tl.ampm(false) != b"AM" {
                                    s.decided = Decided::Loc;
                                }
                                s.clear(PState::IS_PM);
                                break 'start_over;
                            }
                            if match_string(tl.ampm(true), &mut rp) {
                                if tl.ampm(true) != b"PM" {
                                    s.decided = Decided::Loc;
                                }
                                s.set(PState::IS_PM);
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if match_string(b"AM", &mut rp) {
                            s.clear(PState::IS_PM);
                        } else if match_string(b"PM", &mut rp) {
                            s.set(PState::IS_PM);
                        } else {
                            fail!();
                        }
                    }
                    b'r' => {
                        if s.decided != Decided::Raw {
                            if !recursive!(tl.t_fmt_ampm_z()) {
                                if s.decided == Decided::Loc {
                                    fail!();
                                }
                                rp = rp_backup;
                            } else {
                                if s.decided == Decided::Not && tl.t_fmt_ampm() != no_nul(timeloc::C_T_FMT_AMPM) {
                                    s.decided = Decided::Loc;
                                }
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if !recursive!(Fmt::Z(ZStr::from(timeloc::C_T_FMT_AMPM_Z))) {
                            fail!();
                        }
                    }
                    b'R' => {
                        if !recursive!(Fmt::Z(ZStr::from(c"%H:%M"))) {
                            fail!();
                        }
                    }
                    b's' => {
                        let mut secs: i64 = 0;
                        if rp.cur() < b'0' || rp.cur() > b'9' {
                            fail!();
                        }
                        loop {
                            secs = secs.wrapping_mul(10).wrapping_add((rp.cur() - b'0') as i64);
                            rp.bump();
                            if !(rp.cur() >= b'0' && rp.cur() <= b'9') {
                                break;
                            }
                        }
                        if !tz::tz_convert(secs, true, tm, false) {
                            fail!();
                        }
                    }
                    b'S' => {
                        get_number!(0, 61, 2);
                        tm.tm_sec = val as c_int;
                    }
                    b'X' | b'T' => {
                        if conv == b'X' && s.decided != Decided::Raw {
                            if !recursive!(tl.t_fmt_z()) {
                                if s.decided == Decided::Loc {
                                    fail!();
                                }
                                rp = rp_backup;
                            } else {
                                if tl.t_fmt() != no_nul(timeloc::C_T_FMT) {
                                    s.decided = Decided::Loc;
                                }
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if !recursive!(Fmt::Z(ZStr::from(timeloc::C_T_FMT_Z))) {
                            fail!();
                        }
                    }
                    b'u' => {
                        get_number!(1, 7, 1);
                        tm.tm_wday = (val % 7) as c_int;
                        s.set(PState::HAVE_WDAY);
                    }
                    b'g' => {
                        get_number!(0, 99, 2);
                    }
                    b'G' => {
                        if rp.cur() < b'0' || rp.cur() > b'9' {
                            fail!();
                        }
                        loop {
                            rp.bump();
                            if !(rp.cur() >= b'0' && rp.cur() <= b'9') {
                                break;
                            }
                        }
                    }
                    b'U' => {
                        get_number!(0, 53, 2);
                        s.week_no = val as i8;
                        s.set(PState::HAVE_UWEEK);
                    }
                    b'W' => {
                        get_number!(0, 53, 2);
                        s.week_no = val as i8;
                        s.set(PState::HAVE_WWEEK);
                    }
                    b'V' => {
                        get_number!(0, 53, 2);
                    }
                    b'w' => {
                        get_number!(0, 6, 1);
                        tm.tm_wday = val as c_int;
                        s.set(PState::HAVE_WDAY);
                    }
                    b'y' => {
                        get_number!(0, 99, 2);
                        tm.tm_year = if val >= 69 { val as c_int } else { val as c_int + 100 };
                        s.set(PState::WANT_CENTURY);
                        s.set(PState::WANT_XDAY);
                    }
                    b'Y' => {
                        get_number!(0, 9999, 4);
                        tm.tm_year = val as c_int - 1900;
                        s.clear(PState::WANT_CENTURY);
                        s.set(PState::WANT_XDAY);
                    }
                    b'Z' => {
                        while isspace_c(rp.cur()) {
                            rp.bump();
                        }
                        while !isspace_c(rp.cur()) && rp.cur() != 0 {
                            rp.bump();
                        }
                    }
                    b'z' => {
                        val = 0;
                        while isspace_c(rp.cur()) {
                            rp.bump();
                        }
                        if rp.cur() == b'Z' {
                            rp.bump();
                            tm.tm_gmtoff = 0;
                        } else {
                            if rp.cur() != b'+' && rp.cur() != b'-' {
                                fail!();
                            }
                            let neg = rp.cur() == b'-';
                            rp.bump();
                            let mut n = 0;
                            while n < 4 && rp.cur() >= b'0' && rp.cur() <= b'9' {
                                val = val * 10 + (rp.cur() - b'0') as usize;
                                rp.bump();
                                n += 1;
                                if rp.cur() == b':' && n == 2 && rp.peek(1).is_ascii_digit() {
                                    rp.bump();
                                }
                            }
                            if n == 2 {
                                val *= 100;
                            } else if n != 4 || val % 100 >= 60 {
                                fail!();
                            }
                            let off = ((val / 100) * 3600 + (val % 100) * 60) as i64;
                            tm.tm_gmtoff = if neg { -off } else { off } as _;
                        }
                    }
                    b'E' => {
                        let m = fz.cur();
                        fz.bump();
                        match m {
                            b'c' => {
                                if s.decided != Decided::Raw {
                                    let e2 = tl.era_d_t_fmt();
                                    let (f2, f2s) = if e2.is_empty() { (tl.d_t_fmt_z(), tl.d_t_fmt()) } else { (Fmt::S(e2), e2) };
                                    if !recursive!(f2) {
                                        if s.decided == Decided::Loc {
                                            fail!();
                                        }
                                        rp = rp_backup;
                                    } else {
                                        if f2s != no_nul(timeloc::C_D_T_FMT) {
                                            s.decided = Decided::Loc;
                                        }
                                        s.set(PState::WANT_XDAY);
                                        break 'start_over;
                                    }
                                    s.decided = Decided::Raw;
                                }
                                if !recursive!(Fmt::Z(ZStr::from(timeloc::C_D_T_FMT_Z))) {
                                    fail!();
                                }
                                s.set(PState::WANT_XDAY);
                            }
                            b'C' => {
                                if s.decided != Decided::Raw {
                                    if s.era_cnt >= 0 {
                                        match tl.era(s.era_cnt as usize) {
                                            Some(e) if match_string(e.name, &mut rp) => {
                                                s.decided = Decided::Loc;
                                                break 'start_over;
                                            }
                                            _ => fail!(),
                                        }
                                    }
                                    let n = tl.era_count() as i32;
                                    s.era_cnt = 0;
                                    while s.era_cnt < n {
                                        if let Some(e) = tl.era(s.era_cnt as usize)
                                            && match_string(e.name, &mut rp)
                                        {
                                            s.decided = Decided::Loc;
                                            break;
                                        }
                                        s.era_cnt += 1;
                                        rp = rp_backup;
                                    }
                                    if s.era_cnt != n {
                                        break 'start_over;
                                    }
                                    s.era_cnt = -1;
                                    if s.decided == Decided::Loc {
                                        fail!();
                                    }
                                    s.decided = Decided::Raw;
                                }
                                get_number!(0, 99, 2);
                                s.century = val as i8;
                                s.set(PState::WANT_XDAY);
                            }
                            b'y' => {
                                if s.decided != Decided::Raw {
                                    get_number!(0, 9999, 4);
                                    tm.tm_year = val as c_int;
                                    s.set(PState::WANT_ERA);
                                    s.set(PState::WANT_XDAY);
                                    s.set(PState::WANT_CENTURY);
                                    // does year `tm.tm_year` of era `e` exist?
                                    let in_era = |e: &timeloc::Era, year: c_int| -> bool {
                                        let delta = (year - e.offset) * e.absolute_direction;
                                        delta >= 0 && (delta as i64) < ((e.stop_date[0] as i64 - e.start_date[0] as i64) * e.absolute_direction as i64 + 1)
                                    };
                                    if s.era_cnt >= 0 {
                                        match tl.era(s.era_cnt as usize) {
                                            Some(e) if in_era(&e, tm.tm_year) => break 'start_over,
                                            _ => fail!(),
                                        }
                                    }
                                    let n = tl.era_count() as i32;
                                    s.era_cnt = 0;
                                    while s.era_cnt < n {
                                        if let Some(e) = tl.era(s.era_cnt as usize)
                                            && in_era(&e, tm.tm_year)
                                        {
                                            s.decided = Decided::Loc;
                                            break;
                                        }
                                        s.era_cnt += 1;
                                    }
                                    if s.era_cnt != n {
                                        break 'start_over;
                                    }
                                    s.era_cnt = -1;
                                    if s.decided == Decided::Loc {
                                        fail!();
                                    }
                                    s.decided = Decided::Raw;
                                }
                                get_number!(0, 99, 2);
                                tm.tm_year = if val >= 69 { val as c_int } else { val as c_int + 100 };
                                s.set(PState::WANT_CENTURY);
                                s.set(PState::WANT_XDAY);
                            }
                            b'Y' => {
                                if s.decided != Decided::Raw {
                                    let n = tl.era_count() as i32;
                                    s.era_cnt = 0;
                                    while s.era_cnt < n {
                                        if let Some(e) = tl.era(s.era_cnt as usize)
                                            && recursive!(Fmt::S(e.format))
                                        {
                                            break;
                                        }
                                        s.era_cnt += 1;
                                        rp = rp_backup;
                                    }
                                    if s.era_cnt == n {
                                        s.era_cnt = -1;
                                        if s.decided == Decided::Loc {
                                            fail!();
                                        }
                                        rp = rp_backup;
                                    } else {
                                        s.decided = Decided::Loc;
                                        break 'start_over;
                                    }
                                    s.decided = Decided::Raw;
                                }
                                get_number!(0, 9999, 4);
                                tm.tm_year = val as c_int - 1900;
                                s.clear(PState::WANT_CENTURY);
                                s.set(PState::WANT_XDAY);
                            }
                            b'x' => {
                                if s.decided != Decided::Raw {
                                    let e2 = tl.era_d_fmt();
                                    let (f2, f2s) = if e2.is_empty() { (tl.d_fmt_z(), tl.d_fmt()) } else { (Fmt::S(e2), e2) };
                                    if !recursive!(f2) {
                                        if s.decided == Decided::Loc {
                                            fail!();
                                        }
                                        rp = rp_backup;
                                    } else {
                                        if f2s != no_nul(timeloc::C_D_FMT) {
                                            s.decided = Decided::Loc;
                                        }
                                        break 'start_over;
                                    }
                                    s.decided = Decided::Raw;
                                }
                                if !recursive!(Fmt::Z(ZStr::from(timeloc::C_D_FMT_Z))) {
                                    fail!();
                                }
                            }
                            b'X' => {
                                if s.decided != Decided::Raw {
                                    let e2 = tl.era_t_fmt();
                                    let (f2, f2s) = if e2.is_empty() { (tl.t_fmt_z(), tl.t_fmt()) } else { (Fmt::S(e2), e2) };
                                    if !recursive!(f2) {
                                        if s.decided == Decided::Loc {
                                            fail!();
                                        }
                                        rp = rp_backup;
                                    } else {
                                        if f2s != no_nul(timeloc::C_T_FMT) {
                                            s.decided = Decided::Loc;
                                        }
                                        break 'start_over;
                                    }
                                    s.decided = Decided::Raw;
                                }
                                if !recursive!(Fmt::Z(ZStr::from(timeloc::C_T_FMT_Z))) {
                                    fail!();
                                }
                            }
                            _ => fail!(),
                        }
                    }
                    b'O' => {
                        let at_m = fz;
                        let m = fz.cur();
                        fz.bump();
                        match m {
                            b'b' | b'B' | b'h' => {
                                fz = at_m;
                                continue 'start_over;
                            }
                            b'd' | b'e' => {
                                get_alt_number!(1, 31, 2);
                                tm.tm_mday = val as c_int;
                                s.set(PState::HAVE_MDAY);
                                s.set(PState::WANT_XDAY);
                            }
                            b'H' => {
                                get_alt_number!(0, 23, 2);
                                tm.tm_hour = val as c_int;
                                s.clear(PState::HAVE_I);
                            }
                            b'I' => {
                                get_alt_number!(1, 12, 2);
                                tm.tm_hour = (val % 12) as c_int;
                                s.set(PState::HAVE_I);
                            }
                            b'm' => {
                                get_alt_number!(1, 12, 2);
                                tm.tm_mon = val as c_int - 1;
                                s.set(PState::HAVE_MON);
                                s.set(PState::WANT_XDAY);
                            }
                            b'M' => {
                                get_alt_number!(0, 59, 2);
                                tm.tm_min = val as c_int;
                            }
                            b'S' => {
                                get_alt_number!(0, 61, 2);
                                tm.tm_sec = val as c_int;
                            }
                            b'U' => {
                                get_alt_number!(0, 53, 2);
                                s.week_no = val as i8;
                                s.set(PState::HAVE_UWEEK);
                            }
                            b'W' => {
                                get_alt_number!(0, 53, 2);
                                s.week_no = val as i8;
                                s.set(PState::HAVE_WWEEK);
                            }
                            b'V' => {
                                get_alt_number!(0, 53, 2);
                            }
                            b'w' => {
                                get_alt_number!(0, 6, 1);
                                tm.tm_wday = val as c_int;
                                s.set(PState::HAVE_WDAY);
                            }
                            b'y' => {
                                get_alt_number!(0, 99, 2);
                                tm.tm_year = if val >= 69 { val as c_int } else { val as c_int + 100 };
                                s.set(PState::WANT_XDAY);
                            }
                            _ => fail!(),
                        }
                    }
                    _ => fail!(),
                }
                break;
            }
        }

        if let Some(st) = state {
            *st = s;
            return Some(rp);
        }

        if s.has(PState::HAVE_I) && s.has(PState::IS_PM) {
            tm.tm_hour += 12;
        }
        if s.century != -1 {
            if s.has(PState::WANT_CENTURY) {
                tm.tm_year = tm.tm_year % 100 + (s.century as c_int - 19) * 100;
            } else {
                tm.tm_year = (s.century as c_int - 19) * 100;
            }
        }
        if s.era_cnt != -1 {
            let e = tl.era(s.era_cnt as usize)?;
            if s.has(PState::WANT_ERA) {
                tm.tm_year = e.start_date[0] + (tm.tm_year - e.offset) * e.absolute_direction;
            } else {
                // era start year assumed
                tm.tm_year = e.start_date[0];
            }
        } else if s.has(PState::WANT_ERA) && s.has(PState::WANT_CENTURY) && s.century == -1 && tm.tm_year < 69 {
            tm.tm_year += 100;
        }
        let mon_ok = |tm: &Tm, s: &PState| s.has(PState::HAVE_MON) || (tm.tm_mon as u32) <= 11;
        if s.has(PState::WANT_XDAY) && !s.has(PState::HAVE_WDAY) {
            if !(s.has(PState::HAVE_MON) && s.has(PState::HAVE_MDAY)) && s.has(PState::HAVE_YDAY) {
                let leap = isleap(1900 + tm.tm_year);
                let mut t_mon = 0usize;
                while t_mon < 40 && mon_yday(leap, t_mon as isize) <= tm.tm_yday {
                    t_mon += 1;
                }
                if !s.has(PState::HAVE_MON) {
                    tm.tm_mon = t_mon as c_int - 1;
                }
                if !s.has(PState::HAVE_MDAY) {
                    tm.tm_mday = tm.tm_yday - mon_yday(leap, t_mon as isize - 1) + 1;
                }
                s.set(PState::HAVE_MON);
                s.set(PState::HAVE_MDAY);
            }
            if mon_ok(tm, &s) {
                day_of_the_week(tm);
            }
        }
        if s.has(PState::WANT_XDAY) && !s.has(PState::HAVE_YDAY) && mon_ok(tm, &s) {
            day_of_the_year(tm);
        }
        if (s.has(PState::HAVE_UWEEK) || s.has(PState::HAVE_WWEEK)) && s.has(PState::HAVE_WDAY) {
            let save_wday = tm.tm_wday;
            let save_mday = tm.tm_mday;
            let save_mon = tm.tm_mon;
            let w_offset = if s.has(PState::HAVE_UWEEK) { 0 } else { 1 };
            tm.tm_mday = 1;
            tm.tm_mon = 0;
            day_of_the_week(tm);
            if s.has(PState::HAVE_MDAY) {
                tm.tm_mday = save_mday;
            }
            if s.has(PState::HAVE_MON) {
                tm.tm_mon = save_mon;
            }
            if !s.has(PState::HAVE_YDAY) {
                tm.tm_yday = (7 - (tm.tm_wday - w_offset)) % 7 + (s.week_no as c_int - 1) * 7 + (save_wday - w_offset + 7) % 7;
            }
            if !s.has(PState::HAVE_MDAY) || !s.has(PState::HAVE_MON) {
                let leap = isleap(1900 + tm.tm_year);
                let mut t_mon = 0usize;
                while t_mon < 40 && mon_yday(leap, t_mon as isize) <= tm.tm_yday {
                    t_mon += 1;
                }
                if !s.has(PState::HAVE_MON) {
                    tm.tm_mon = t_mon as c_int - 1;
                }
                if !s.has(PState::HAVE_MDAY) {
                    tm.tm_mday = tm.tm_yday - mon_yday(leap, t_mon as isize - 1) + 1;
                }
            }
            tm.tm_wday = save_wday;
        }
        Some(rp)
    }
}

/// The engine behind `strptime` and `strptime_l`.
///
/// # Safety
/// As `strptime`.
unsafe fn strptime_c(buf: *const c_char, format: *const c_char, tm: *mut Tm, tl: &TimeLoc) -> *mut c_char {
    // SAFETY: `buf` is a C string (the C contract; a NULL faults on the first read, as in glibc).
    let input = unsafe { ZStr::new(buf.cast::<u8>()) };
    // SAFETY: `format` is a C string (as `buf`).
    let fmt = unsafe { ZStr::new(format.cast::<u8>()) };
    // SAFETY: `tm` is the caller's struct tm, not otherwise accessed during the call (a NULL faults, as in glibc).
    let tm = unsafe { sys::arg_mut(tm) };
    match strptime_internal(input, fmt, tm, None, tl) {
        // the first character not consumed: inside the input string or its NUL
        Some(end) => buf.wrapping_add(end.pos()).cast_mut(),
        None => core::ptr::null_mut(),
    }
}

/// `char *strptime(const char *buf, const char *format, struct tm *tm)`: returns the first
/// character not consumed, or NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strptime(buf: *const c_char, format: *const c_char, tm: *mut Tm) -> *mut c_char {
    // SAFETY: the caller's contract is strptime's.
    unsafe { strptime_c(buf, format, tm, &TimeLoc::current()) }
}

/// `char *strptime_l(...)`: the names and formats of `loc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strptime_l(buf: *const c_char, format: *const c_char, tm: *mut Tm, loc: LocaleT) -> *mut c_char {
    // SAFETY: `loc` is a locale_t or LC_GLOBAL_LOCALE (the caller's contract).
    let tl = unsafe { TimeLoc::of_locale(loc as usize) };
    // SAFETY: the caller's contract is strptime's.
    unsafe { strptime_c(buf, format, tm, &tl) }
}

/// `strptime` on slices, the Rust API: parse `input` (it ends at its first NUL, like the C string) with `format` into
/// `tm`; the number of bytes consumed, or None.
/// (The engine reads NUL-terminated strings: a slice without a NUL is run on a NUL-terminated copy, so None also when a
/// copy longer than 127 bytes cannot be allocated.)
pub fn parse(input: &[u8], format: &[u8], tm: &mut Tm) -> Option<usize> {
    let tl = TimeLoc::current();
    let with = |s: &[u8], f: &mut dyn FnMut(ZStr<'_, u8>) -> Option<usize>| -> Option<usize> {
        match ZStr::from_slice(s) {
            Some(z) => f(z),
            None => with_nul(s, &mut *f).flatten(),
        }
    };
    with(input, &mut |zi| with(format, &mut |zf| strptime_internal(zi, zf, tm, None, &tl).map(|e| e.pos())))
}

// ------------------------------------------------------------------ getdate

// (a C `int` object programs read; written with relaxed stores: same size and alignment as `int`)
/// Error code of the last failed `getdate` (1 no DATEMSK ... 8 invalid date).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static getdate_err: AtomicI32 = AtomicI32::new(0);

fn first_wday(year: i32, mon: i32, wday: i32) -> i32 {
    if wday == i32::MIN {
        return 1;
    }
    let mut tm = Tm { tm_year: year, tm_mon: mon, tm_mday: 1, ..Tm::default() };
    calendar::mktime_tm(&mut tm);
    1 + (wday - tm.tm_wday + 7) % 7
}

fn check_mday(year: i32, mon: i32, mday: i32) -> bool {
    match mon {
        0 | 2 | 4 | 6 | 7 | 9 | 11 => (1..=31).contains(&mday),
        3 | 5 | 8 | 10 => (1..=30).contains(&mday),
        1 => (1..=if isleap(year) { 29 } else { 28 }).contains(&mday),
        _ => false,
    }
}

/// `getdate_r` on Rust values: match the input (a C string's bytes, fetched by `input` only once the template file was
/// read, where glibc first reads it) against the templates in the file named by `$DATEMSK`; 0 or the error code.
pub fn getdate_tm<'a>(input: impl FnOnce() -> &'a [u8], tp: &mut Tm) -> c_int {
    let Some(datemsk) = sys::getenv_c(b"DATEMSK").filter(|d| !d.is_empty()) else { return 1 };
    let Ok(st) = sys::stat(datemsk) else { return 3 };
    if st.st_mode & 0o170000 != 0o100000 {
        return 4;
    }
    if sys::access(datemsk, 4).is_err() {
        return 2;
    }
    let Ok(fd) = sys::open_rdonly_cloexec(datemsk) else { return 2 };
    // the whole template file (and a byte for a NUL, as the C buffer had)
    let mut cap = 4096usize;
    let mut data = MBuf::filled(cap + 1, 0u8);
    let mut len = 0usize;
    let mut read_error = data.is_none();
    while let Some(d) = data.as_mut()
        && !read_error
    {
        if len == cap {
            cap *= 2;
            if !d.grow(cap + 1, 0) {
                read_error = true;
                break;
            }
        }
        match rusty_libc_core::unistd::read_nocancel(fd, &mut d[len..cap]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.0 == rusty_libc_core::errno::EINTR => {}
            Err(_) => {
                read_error = true;
            }
        }
    }
    let _ = rusty_libc_core::unistd::close(fd);
    let Some(data) = data else { return 6 };
    if read_error {
        return 5;
    }
    // the input: leading and trailing white space removed (copied, as glibc does: a failed copy is error 6)
    let input = input();
    let mut start = 0;
    while start < input.len() && isspace_c(input[start]) {
        start += 1;
    }
    let mut end = input.len();
    while end > start && isspace_c(input[end - 1]) {
        end -= 1;
    }
    let inlen = end - start;
    let Some(mut instr) = MBuf::filled(inlen + 1, 0u8) else { return 6 };
    instr[..inlen].copy_from_slice(&input[start..end]);

    let mut found = false;
    let mut pos = 0usize;
    while pos < len {
        let line_start = pos;
        while pos < len && data[pos] != b'\n' {
            pos += 1;
        }
        let line = &data[line_start..pos];
        if pos < len {
            pos += 1; // the newline ends the line
        }
        tp.tm_year = i32::MIN;
        tp.tm_mon = i32::MIN;
        tp.tm_mday = i32::MIN;
        tp.tm_wday = i32::MIN;
        tp.tm_hour = i32::MIN;
        tp.tm_sec = i32::MIN;
        tp.tm_min = i32::MIN;
        tp.tm_isdst = -1;
        tp.tm_gmtoff = 0;
        tp.tm_zone = core::ptr::null();
        // (the input copy holds no NUL: it came from a C string; the template line is matched up to a NUL in it, as the
        // C string it stands for)
        let zin = ZStr::from_nul_terminated(&instr).unwrap_or(ZStr::from(c""));
        if with_nul(line, |zl| strptime_internal(zin, zl, tp, None, &TimeLoc::current()).map(|e| e.pos())).flatten() == Some(inlen) {
            found = true;
            break;
        }
    }
    drop(data);
    if !found {
        return 7;
    }
    let timer = crate::clock::unix_time();
    let mut tm = Tm::default();
    tz::tz_convert(timer, true, &mut tm, false);
    let mut mday_ok = false;
    if (0..=6).contains(&tp.tm_wday) && tp.tm_year == i32::MIN && tp.tm_mon == i32::MIN && tp.tm_mday == i32::MIN {
        tp.tm_year = tm.tm_year;
        tp.tm_mon = tm.tm_mon;
        tp.tm_mday = tm.tm_mday + (tp.tm_wday - tm.tm_wday + 7) % 7;
        mday_ok = true;
    }
    if (0..=11).contains(&tp.tm_mon) && tp.tm_mday == i32::MIN {
        if tp.tm_year == i32::MIN {
            tp.tm_year = tm.tm_year + if tp.tm_mon - tm.tm_mon < 0 { 1 } else { 0 };
        }
        tp.tm_mday = first_wday(tp.tm_year, tp.tm_mon, tp.tm_wday);
        mday_ok = true;
    }
    if tp.tm_hour == i32::MIN && tp.tm_min == i32::MIN && tp.tm_sec == i32::MIN {
        tp.tm_hour = tm.tm_hour;
        tp.tm_min = tm.tm_min;
        tp.tm_sec = tm.tm_sec;
    }
    if tp.tm_hour == i32::MIN {
        tp.tm_hour = 0;
    }
    if tp.tm_min == i32::MIN {
        tp.tm_min = 0;
    }
    if tp.tm_sec == i32::MIN {
        tp.tm_sec = 0;
    }
    if (0..=23).contains(&tp.tm_hour) && tp.tm_mon == i32::MIN && tp.tm_mday == i32::MIN && tp.tm_wday == i32::MIN {
        tp.tm_mon = tm.tm_mon;
        tp.tm_mday = tm.tm_mday + if tp.tm_hour - tm.tm_hour < 0 { 1 } else { 0 };
        mday_ok = true;
    }
    if tp.tm_year == i32::MIN {
        tp.tm_year = tm.tm_year;
    }
    if tp.tm_mon == i32::MIN {
        tp.tm_mon = tm.tm_mon;
    }
    if (!mday_ok && !check_mday(1900i32.wrapping_add(tp.tm_year), tp.tm_mon, tp.tm_mday)) || calendar::mktime_tm(tp) == -1 {
        return 8;
    }
    0
}

/// `int getdate_r(const char *string, struct tm *res)`: match `string` against the templates in
/// the file named by `$DATEMSK`; returns 0 or the error code (see `getdate_err`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdate_r(string: *const c_char, tp: *mut Tm) -> c_int {
    // SAFETY: `string` is a C string (the C contract; it is read only after the template file was read, as before).
    let input = || unsafe { ffi::cstr_bytes(string) };
    // SAFETY: `tp` is the caller's struct tm, not otherwise accessed during the call (a NULL faults, as in glibc).
    let tp = unsafe { sys::arg_mut(tp) };
    getdate_tm(input, tp)
}

/// The static result of `getdate`.
static GETDATE_TM: SyncCell<Tm> = SyncCell::new(Tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() });

/// `struct tm *getdate(const char *string)`: static result; NULL with `getdate_err` set.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdate(string: *const c_char) -> *mut Tm {
    // SAFETY: `string` is a C string (the C contract).
    let input = || unsafe { ffi::cstr_bytes(string) };
    // SAFETY: getdate is not thread-safe (its result and `getdate_err` are shared, as in glibc): the caller does not run
    // it in two threads at once, so nothing else touches the static result during the call.
    let e = unsafe { GETDATE_TM.with_unsync(|tm| getdate_tm(input, tm)) };
    if e != 0 {
        getdate_err.store(e, Relaxed);
        return core::ptr::null_mut();
    }
    GETDATE_TM.as_ptr()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::testutil::*;
    use std::ffi::{CStr, CString};

    unsafe extern "C" {
        #[link_name = "strftime"]
        fn host_strftime(s: *mut c_char, max: usize, f: *const c_char, tm: *const libc::tm) -> usize;
        #[link_name = "strptime"]
        fn host_strptime(s: *const c_char, f: *const c_char, tm: *mut libc::tm) -> *mut c_char;
        #[link_name = "getdate_r"]
        fn host_getdate_r(s: *const c_char, tm: *mut libc::tm) -> c_int;
        #[link_name = "getdate_err"]
        static HOST_GETDATE_ERR: c_int;
        #[link_name = "getdate"]
        fn host_getdate(s: *const c_char) -> *mut libc::tm;
    }

    static ZONES: [&CStr; 4] = [c"", c"XYZ", c"Europe/Nowhere", c"UTC"];

    fn tm_with_zone(rng: &mut Rng, tm: &mut Tm) {
        tm.tm_zone = match rng.range(0, 3) {
            0 => core::ptr::null(),
            1 => ZONES[0].as_ptr(),
            _ => ZONES[rng.range(1, 3) as usize].as_ptr(),
        };
        tm.tm_gmtoff = *rng.pick(&[0, 3600, -18000, 19800, -12600, 86399, -86399, 1, -1, 45_296]);
    }

    /// `localtime_r` on ours and on the host, so that `tzname` (which it rewrites) stays equal.
    fn local_both(t: i64) -> Option<Tm> {
        let mut h: libc::tm = unsafe { core::mem::zeroed() };
        unsafe { libc::localtime_r(&t, &mut h) };
        crate::calendar::to_local(t).ok()
    }

    /// A tm that is mostly consistent (from `gmtime`), sometimes random or out of range.
    fn pick_tm(rng: &mut Rng) -> Tm {
        let mut tm = match rng.range(0, 5) {
            0 => random_tm(rng),
            1 => {
                let mut tm = random_tm(rng);
                tm.tm_year = rng.range(-3000, 12000) as i32;
                tm.tm_wday = rng.range(-2, 9) as i32;
                tm.tm_yday = rng.range(-370, 400) as i32;
                tm.tm_mon = rng.range(-2, 13) as i32;
                tm.tm_hour = rng.range(-2, 26) as i32;
                tm
            }
            _ => local_both(random_time(rng) % 4_000_000_000_000).unwrap_or_default(),
        };
        tm_with_zone(rng, &mut tm);
        tm
    }

    fn run_pair(fmt: &CStr, tm: &Tm, max: usize) -> ((usize, Vec<u8>), (usize, Vec<u8>)) {
        let htm = host_tm(tm);
        let mut a = vec![0x55u8; max.max(1)];
        let mut b = vec![0x55u8; max.max(1)];
        let ra = unsafe { strftime(a.as_mut_ptr().cast(), max, fmt.as_ptr(), tm) };
        let rb = unsafe { host_strftime(b.as_mut_ptr().cast(), max, fmt.as_ptr(), &htm) };
        ((ra, a), (rb, b))
    }

    /// Every field out of range, one at a time (ints at both ends, around the calendar's limits), and tm_gmtoff values
    /// that do not fit an int: return value and the whole buffer equal to the host's (glibc 2.43), for every conversion.
    #[test]
    fn strftime_out_of_range_fields() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("UTC"));
        let base = crate::calendar::to_utc(1_760_000_000).unwrap();
        let vals = [i32::MIN, i32::MIN + 1, -1000, -367, -366, -13, -12, -8, -7, -1, 0, 6, 7, 11, 12, 13, 24, 60, 99, 100, 365, 366, 9999, i32::MAX - 1900, i32::MAX - 1899, i32::MAX];
        let fmts = [c"%a %A %b %B %h %Ob %OB", c"%c|%x|%X|%r|%D|%T|%F", c"%C %d %e %g %G %H %I %j %k %l %m %M %p %P %S %u %U %V %w %W %y %Y",
                    c"%Od %Oe %OH %OI %Om %OM %OS %Ou %OU %OV %Ow %OW %Oy %Ey %EC %EY", c"%10a|%-5B|%_9j|%012Y|%^c", c"%z %Ez %Oz %10z"];
        let mut tms = Vec::new();
        for f in 0..8 {
            for &v in &vals {
                let mut tm = base;
                *[&mut tm.tm_sec, &mut tm.tm_min, &mut tm.tm_hour, &mut tm.tm_mday, &mut tm.tm_mon, &mut tm.tm_year, &mut tm.tm_wday, &mut tm.tm_yday][f] = v;
                tms.push(tm);
            }
        }
        for g in [i64::from(i32::MIN), i64::from(i32::MAX), i64::from(i32::MAX) + 1, i64::MIN, -2_147_483_708, 4_294_967_296 + 7200] {
            let mut tm = base;
            tm.tm_gmtoff = g as _;
            tms.push(tm);
        }
        for tm in &tms {
            for f in fmts {
                for max in [200, 9] {
                    let (a, b) = run_pair(f, tm, max);
                    assert_eq!(a, b, "{f:?} max {max} {:?}", (tm.tm_sec, tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon, tm.tm_year, tm.tm_wday, tm.tm_yday, tm.tm_gmtoff));
                }
            }
        }
    }

    #[test]
    fn strftime_known_outputs() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("UTC"));
        let tm = crate::calendar::to_utc(1_709_210_096).unwrap(); // Thu 2024-02-29 12:34:56 UTC
        let mut out = [0u8; 200];
        let mut f = |fmt: &str| -> String {
            let n = format(&mut out, fmt.as_bytes(), &tm).expect("fits");
            String::from_utf8(out[..n].to_vec()).unwrap()
        };
        assert_eq!(f("%Y-%m-%d %H:%M:%S"), "2024-02-29 12:34:56");
        assert_eq!(f("%a %A %b %B %h"), "Thu Thursday Feb February Feb");
        assert_eq!(f("%c"), "Thu Feb 29 12:34:56 2024");
        assert_eq!(f("%x %X %D %F %T %R %r"), "02/29/24 12:34:56 02/29/24 2024-02-29 12:34:56 12:34 12:34:56 PM");
        assert_eq!(f("%C %y %g %G %V %U %W %u %w %j"), "20 24 24 2024 09 08 09 4 4 060");
        assert_eq!(f("%e|%k|%l|%I|%p|%P|%s"), "29|12|12|12|PM|pm|1709210096");
        assert_eq!(f("%z %Z %% %n%t."), "+0000 GMT % \n\t.");
        assert_eq!(f("%_5d|%-d|%05d|%^a|%#A|%#p|%10Y|%_10Y|%-10Y|%3%|%E|%Q|%-"), "   29|29|00029|THU|THURSDAY|pm|0000002024|      2024|      2024|  %|%E|%Q|%-");
        assert_eq!(f("%Ey %Od %OH %EY"), "24 29 12 2024");
        assert_eq!(f("%EH|%Ed|%Oc|%Ox|%OX|%Ea|%OY|%E%"), "%EH|%Ed|%Oc|%Ox|%OX|%Ea|%OY|%");
        // too small
        assert_eq!(format(&mut out[..4], b"%Y-%m", &tm), None);
        assert_eq!(format(&mut out[..8], b"%Y-%m", &tm), Some(7));
        assert_eq!(format(&mut out[..7], b"%Y-%m", &tm), None);
        assert_eq!(format(&mut out, b"", &tm), Some(0));
    }

    #[test]
    fn strftime_matches_host_on_random_formats() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("America/New_York"));
        let mut rng = Rng(0x5eed_1234);
        let convs = b"aAbBcCdDeFgGhHIjklmMnpPrRsStTuUVwWxXyYzZ%QJ+f$q ";
        let flags = b"_-0^#";
        let widths = ["", "", "", "1", "2", "3", "5", "7", "12", "0", "00", "20", "100"];
        let mods = ["", "", "", "E", "O"];
        let mut checked = 0usize;
        for _ in 0..250_000 {
            let tm = pick_tm(&mut rng);
            let mut f = String::new();
            for _ in 0..rng.range(1, 3) {
                if rng.range(0, 3) == 0 {
                    f.push_str(["x", " - ", "::", "é"][rng.range(0, 3) as usize]);
                }
                f.push('%');
                for _ in 0..rng.range(0, 3) {
                    f.push(*rng.pick(flags) as char);
                }
                f.push_str(rng.pick(&widths));
                f.push_str(rng.pick(&mods));
                f.push(*rng.pick(convs) as char);
            }
            if rng.range(0, 40) == 0 {
                f.push('%'); // a lone % at the end
            }
            let cf = CString::new(f.clone()).unwrap();
            let ((ra, a), (rb, b)) = run_pair(&cf, &tm, 600);
            assert_eq!(ra, rb, "fmt {f:?} tm {tm:?}");
            assert_eq!(a[..ra], b[..rb], "fmt {f:?} tm {tm:?}");
            // tight buffers: same success/failure, same bytes written
            for max in [0, 1, rb, rb + 1, rb.saturating_sub(1), rb / 2] {
                let ((ra2, a2), (rb2, b2)) = run_pair(&cf, &tm, max);
                assert_eq!(ra2, rb2, "fmt {f:?} max {max} tm {tm:?}");
                if rb2 > 0 {
                    assert_eq!(a2[..rb2], b2[..rb2], "fmt {f:?} max {max}");
                }
                assert_eq!(a2, b2, "buffer after fmt {f:?} max {max} (partial output included)");
            }
            checked += 1;
        }
        assert_eq!(checked, 250_000);
    }

    #[test]
    fn strftime_every_conversion_over_many_times_and_zones() {
        let _g = lock();
        let _e = EnvGuard::new();
        let mut rng = Rng(8675309);
        let convs = "aAbBcCdDeFgGhHIjklmMnpPrRsStTuUVwWxXyYzZ%";
        for tz in TZS {
            set_tz(*tz);
            for _ in 0..400 {
                let t = random_time(&mut rng);
                let mut tm = match local_both(t) {
                    Some(tm) => tm,
                    None => continue,
                };
                if rng.range(0, 4) == 0 {
                    tm.tm_zone = core::ptr::null(); // %Z then uses tzname[tm_isdst]
                }
                for c in convs.chars() {
                    for pre in ["", "-", "_", "0", "^", "#", "10", "-3", "_8", "^12"] {
                        let f = CString::new(format!("%{pre}{c}")).unwrap();
                        let ((ra, a), (rb, b)) = run_pair(&f, &tm, 300);
                        assert_eq!(ra, rb, "TZ={tz:?} fmt {f:?} tm {tm:?}");
                        assert_eq!(a[..ra], b[..rb], "TZ={tz:?} fmt {f:?} tm {tm:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn strftime_edge_cases() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("UTC"));
        let mut tm = Tm { tm_year: 124, tm_mon: 1, tm_mday: 29, ..Tm::default() };
        tm.tm_zone = c"ZZZ".as_ptr();
        for f in [c"%2147483647d", c"%2147483648d", c"%99999999999Y", c"%1000000000a", c"%", c"%%%", c"%-%", c"%E", c"%O", c"%_", c"%^#_-0", c"%010", c"%0", c"%1"] {
            for max in [0, 1, 5, 64, 100_000] {
                let ((ra, a), (rb, b)) = run_pair(f, &tm, max);
                assert_eq!(ra, rb, "{f:?} max {max}");
                assert_eq!(a, b, "{f:?} max {max}");
            }
        }
        // NULL output pointer is not allowed by the C interface; a zero size is
        let mut buf = [0x55u8; 4];
        assert_eq!(unsafe { strftime(buf.as_mut_ptr().cast(), 0, c"x".as_ptr(), &tm) }, 0);
        assert_eq!(buf, [0x55; 4]);
        assert_eq!(unsafe { strftime_l(buf.as_mut_ptr().cast(), 4, c"ab".as_ptr(), &tm, core::ptr::null_mut()) }, 2);
    }

    // ------------------------------------------------------------ strptime

    fn init_tm() -> Tm {
        Tm { tm_sec: 11, tm_min: 22, tm_hour: 5, tm_mday: 17, tm_mon: 6, tm_year: 99, tm_wday: 3, tm_yday: 100, tm_isdst: 0, tm_gmtoff: 7, tm_zone: core::ptr::null() }
    }

    fn strptime_pair(input: &CStr, fmt: &CStr, ctx: &str) -> bool {
        let mut a = init_tm();
        let mut b = host_tm(&a);
        let ra = unsafe { strptime(input.as_ptr(), fmt.as_ptr(), &mut a) };
        let rb = unsafe { host_strptime(input.as_ptr(), fmt.as_ptr(), &mut b) };
        let off = |r: *const c_char| if r.is_null() { None } else { Some(r as usize - input.as_ptr() as usize) };
        assert_eq!(off(ra), off(rb), "{ctx}: input {input:?} fmt {fmt:?}");
        assert!(same_tm(&a, &ours_tm(&b)), "{ctx}: input {input:?} fmt {fmt:?}\n ours {a:?}\n host {b:?}");
        !rb.is_null()
    }

    const PFMTS: &[&str] = &[
        "%a", "%A", "%b", "%B", "%h", "%c", "%C", "%d", "%e", "%D", "%F", "%H", "%k", "%I", "%l", "%j", "%m", "%M", "%n", "%t", "%p", "%r", "%R", "%s", "%S", "%T", "%u", "%U", "%V", "%g", "%G", "%w", "%W", "%x", "%X", "%y", "%Y", "%z", "%Z", "%%", "%Ec", "%EC", "%Ex", "%EX", "%Ey", "%EY", "%Ed", "%Od", "%Oe", "%OH", "%OI", "%Om", "%OM", "%OS", "%OU", "%OW", "%OV", "%Ow", "%Oy", "%Ob", "%OB", "%Oh", "%Oa", "%-d", "%_d", "%0d", "%^a", "%#b", "%3d", "%10Y", "%Y-%m-%d", "%H:%M:%S", "%a %b %e %H:%M:%S %Y", "%a, %d %b %Y %H:%M:%S %z", "%Y%m%d", "%Y%m%dT%H%M%S%z", "%I:%M %p", "%U %a", "%W %u", "%U %w %Y", "%W %A %Y", "%j %Y", "%C %y", "%y %C", "%EC%Oy", "%Ey%Ey", "%Od %Od", "%Od %e", "%Ob %a", "%a %Od", "%EC %a", "%Ey %a %A", "%a %a", "%A %b %B", " %d  %m ", "%d/%m/%y", "%m/%d/%Y %I:%M:%S %p", "%e%n%t%k", "%H%M", "%Z %z", "x%dy", "%q", "%E", "%O", "%Ez", "%Oz", "%", "%d%", "", " ", "abc",
    ];

    const TOKENS: &[&str] = &[
        "Mon", "Monday", "SUN", "sat", "Tuesday", "Wednesday", "jan", "March", "SEPTEMBER", "Dec", "may", "12", "7", "07", "2024", "99", "68", "69", "00", "001", "366", "367", "61", "60", "59", "53", "54", "24", "23", "13", "0", "pm", "AM", "Pm", "+0530", "-0800", "+05", "-05:30", "+5", "+0560", "Z", " ", "  ", "\t", "\n", ":", "-", "/", "T", "UTC", "%", "x", "", "1709210096", "-1", "+1", "99999", "12345678901234567890", ",", ".", "Janu", "Marchx", "Thursdayy", "Su", "é",
    ];

    #[test]
    fn strptime_matches_host_on_random_inputs() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("America/New_York"));
        let mut rng = Rng(0xfeed_f00d);
        let mut accepted = 0usize;
        let total = 300_000;
        for i in 0..total {
            let fmt = CString::new(*rng.pick(PFMTS)).unwrap();
            let mut input = String::new();
            for _ in 0..rng.range(0, 5) {
                input.push_str(rng.pick(TOKENS));
                if rng.range(0, 3) == 0 {
                    input.push(' ');
                }
            }
            let cin = CString::new(input).unwrap();
            if strptime_pair(&cin, &fmt, &format!("random #{i}")) {
                accepted += 1;
            }
        }
        // a useful share of the inputs must have been accepted, or the comparison proves little
        assert!(accepted > total / 20, "only {accepted} of {total} accepted");
    }

    #[test]
    fn strptime_round_trips_strftime_output() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("Europe/London"));
        let mut rng = Rng(0xabcdef);
        let fmts: Vec<&str> = PFMTS.iter().copied().filter(|f| f.len() > 1).collect();
        let mut accepted = 0usize;
        for i in 0..60_000 {
            let tm = pick_tm(&mut rng);
            let fmt = *rng.pick(&fmts);
            let cf = CString::new(fmt).unwrap();
            let ((ra, a), _) = run_pair(&cf, &tm, 300);
            if ra == 0 && !fmt.is_empty() {
                continue;
            }
            let mut text = a[..ra].to_vec();
            if rng.range(0, 6) == 0 && !text.is_empty() {
                let k = rng.range(0, text.len() as i64 - 1) as usize;
                text[k] = *rng.pick(b"0123456789 :-+aXZ");
            }
            if rng.range(0, 6) == 0 {
                text.extend_from_slice(b" trailing");
            }
            let Ok(cin) = CString::new(text) else { continue };
            if strptime_pair(&cin, &cf, &format!("round trip #{i}")) {
                accepted += 1;
            }
        }
        assert!(accepted > 10_000, "{accepted}");
    }

    #[test]
    fn strptime_known_results() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("UTC"));
        unsafe {
            let mut tm = Tm::default();
            let r = strptime(c"2024-02-29 12:34:56 tail".as_ptr(), c"%Y-%m-%d %H:%M:%S".as_ptr(), &mut tm);
            assert_eq!(CStr::from_ptr(r).to_str().unwrap(), " tail");
            assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday, tm.tm_yday), (124, 1, 29, 12, 34, 56, 4, 59));
            let mut tm = Tm::default();
            assert!(!strptime(c"Thu, 29 Feb 2024 12:34:56 +0530".as_ptr(), c"%a, %d %b %Y %H:%M:%S %z".as_ptr(), &mut tm).is_null());
            assert_eq!(tm.tm_gmtoff, 19800);
            let mut tm = Tm::default();
            let r = strptime(c"12:05 PM".as_ptr(), c"%I:%M %p".as_ptr(), &mut tm);
            assert!(!r.is_null());
            assert_eq!((tm.tm_hour, tm.tm_min), (12, 5));
            let mut tm = Tm::default();
            let r = strptime(c"1709210096".as_ptr(), c"%s".as_ptr(), &mut tm);
            assert!(!r.is_null());
            assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour), (124, 1, 29, 12));
            assert!(strptime(c"2024-13-01".as_ptr(), c"%Y-%m-%d".as_ptr(), &mut tm).is_null());
            assert!(strptime(c"".as_ptr(), c"%Y".as_ptr(), &mut tm).is_null());
            assert_eq!(strptime(c"abc".as_ptr(), c"".as_ptr(), &mut tm).cast_const(), c"abc".as_ptr().cast_mut().cast_const());
        }
    }

    // ------------------------------------------------------------ getdate

    #[test]
    fn getdate_matches_host() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("UTC"));
        let dir = std::env::temp_dir().join(format!("libc-time-getdate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let msk = dir.join("datemsk");
        std::fs::write(&msk, "%m/%d/%y\n%Y-%m-%d %H:%M:%S\n%Y-%m-%d\n%A\n%B\n%H:%M\n%I %p\n%d %B %Y\n").unwrap();
        let old = std::env::var("DATEMSK").ok();
        let full = |s: &CStr| -> (c_int, Tm) {
            let mut a = Tm::default();
            let mut b: libc::tm = unsafe { core::mem::zeroed() };
            let ra = unsafe { getdate_r(s.as_ptr(), &mut a) };
            let rb = unsafe { host_getdate_r(s.as_ptr(), &mut b) };
            assert_eq!(ra, rb, "getdate_r({s:?})");
            if rb == 0 {
                let hb = ours_tm(&b);
                // dates that depend on "now" are only compared by day (the clock may tick between calls)
                let mut x = a;
                let mut y = hb;
                x.tm_sec = 0;
                y.tm_sec = 0;
                x.tm_min = 0;
                y.tm_min = 0;
                assert!(same_tm(&x, &y) || (a.tm_hour != hb.tm_hour), "getdate_r({s:?}): {a:?} vs {hb:?}");
            }
            (ra, a)
        };
        unsafe {
            // no DATEMSK: 1
            std::env::remove_var("DATEMSK");
            assert_eq!(full(c"01/02/03").0, 1);
            std::env::set_var("DATEMSK", "");
            assert_eq!(full(c"01/02/03").0, 1);
            // missing file: 3, directory: 4
            std::env::set_var("DATEMSK", dir.join("nope"));
            assert_eq!(full(c"01/02/03").0, 3);
            std::env::set_var("DATEMSK", &dir);
            assert_eq!(full(c"01/02/03").0, 4);
            std::env::set_var("DATEMSK", &msk);
        }
        for input in ["02/29/24", "  03/04/05  ", "2024-02-29 12:34:56", "2024-02-30", "2023-02-29", "2024-04-31", "Monday", "tuesday", "March", "december", "13:45", "7 PM", "5 am", "1 January 2030", "31 February 2030", "garbage", "", "99/99/99", "2024-02-29 25:00:00", "Sunday extra", "\t01/02/03\n"] {
            let c = CString::new(input).unwrap();
            full(&c);
        }
        // fixed results
        let mut tm = Tm::default();
        assert_eq!(unsafe { getdate_r(c"2024-02-29 12:34:56".as_ptr(), &mut tm) }, 0);
        assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_wday, tm.tm_yday), (124, 1, 29, 12, 4, 59));
        assert_eq!(unsafe { getdate_r(c"2023-02-29".as_ptr(), &mut tm) }, 8);
        assert_eq!(unsafe { getdate_r(c"nothing like it".as_ptr(), &mut tm) }, 7);
        // getdate sets getdate_err and returns a static tm
        unsafe {
            let p = getdate(c"2024-02-29 01:02:03".as_ptr());
            let hp = host_getdate(c"2024-02-29 01:02:03".as_ptr());
            assert!(!p.is_null() && !hp.is_null());
            assert!(same_tm(&*p, &ours_tm(&*hp)));
            assert!(getdate(c"zzz".as_ptr()).is_null());
            assert!(host_getdate(c"zzz".as_ptr()).is_null());
            let ours_err = getdate_err.load(core::sync::atomic::Ordering::Relaxed);
            assert_eq!(ours_err, HOST_GETDATE_ERR);
            assert_eq!(ours_err, 7);
            // an unreadable template file: 2 (skipped when running as root)
            if libc::geteuid() != 0 {
                let secret = dir.join("secret");
                std::fs::write(&secret, "%Y\n").unwrap();
                std::fs::set_permissions(&secret, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
                std::env::set_var("DATEMSK", &secret);
                assert_eq!(full(c"2024").0, 2);
            }
            match old {
                Some(v) => std::env::set_var("DATEMSK", v),
                None => std::env::remove_var("DATEMSK"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// glibc's strong aliases of the `_l` functions (libstdc++ imports them by these names).
rusty_libc_core::tail_alias!(__strftime_l => strftime_l);
