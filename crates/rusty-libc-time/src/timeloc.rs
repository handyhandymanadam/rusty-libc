//! The LC_TIME data strftime and strptime need: names, formats, eras and alternative digits of the
//! current locale (or of a `locale_t` argument), with the C locale's values when there is no
//! locale data. Item numbers are glibc's; the era table is the binary form glibc's locale files
//! keep in `_NL_TIME_ERA_ENTRIES` (see glibc's time/era.c, LGPL).
//!
//! Everything is handed out as `&'static` slices (locale data is published once and lives for ever). Unsafe here: the walks
//! over the binary era table and the lists of alternative digits, whose lengths are only known by scanning for NULs.
use core::ffi::CStr;
use rusty_libc_core::locale::{self, CatData, F_PLAIN, idx};
use rusty_libc_stdlib::zstr::ZStr;

const WEEKDAY: [&[u8]; 7] = [b"Sunday", b"Monday", b"Tuesday", b"Wednesday", b"Thursday", b"Friday", b"Saturday"];
const AB_WEEKDAY: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTH: [&[u8]; 12] = [b"January", b"February", b"March", b"April", b"May", b"June", b"July", b"August", b"September", b"October", b"November", b"December"];
const AB_MONTH: [&[u8]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

/// A byte string widened to `wchar_t` units, at compile time.
const fn widen<const N: usize>(s: &[u8]) -> [u32; N] {
    let mut w = [0u32; N];
    let mut i = 0;
    while i < N {
        w[i] = s[i] as u32;
        i += 1;
    }
    w
}
macro_rules! wide {
    ($($s:expr),*) => {
        [$({
            const S: &[u8] = $s;
            const W: [u32; S.len()] = widen(S);
            &W
        }),*]
    };
}
/// The C locale's names as wide strings, for `wcsftime` (widened once here instead of on every call: a name widened into
/// a scratch array and copied out at once was read back before its stores had retired, FIXLIST #89).
pub const W_WEEKDAY: [&[u32]; 7] = wide!(WEEKDAY[0], WEEKDAY[1], WEEKDAY[2], WEEKDAY[3], WEEKDAY[4], WEEKDAY[5], WEEKDAY[6]);
pub const W_AB_WEEKDAY: [&[u32]; 7] =
    wide!(AB_WEEKDAY[0], AB_WEEKDAY[1], AB_WEEKDAY[2], AB_WEEKDAY[3], AB_WEEKDAY[4], AB_WEEKDAY[5], AB_WEEKDAY[6]);
pub const W_MONTH: [&[u32]; 12] = wide!(
    MONTH[0], MONTH[1], MONTH[2], MONTH[3], MONTH[4], MONTH[5], MONTH[6], MONTH[7], MONTH[8], MONTH[9], MONTH[10], MONTH[11]
);
pub const W_AB_MONTH: [&[u32]; 12] = wide!(
    AB_MONTH[0], AB_MONTH[1], AB_MONTH[2], AB_MONTH[3], AB_MONTH[4], AB_MONTH[5], AB_MONTH[6], AB_MONTH[7], AB_MONTH[8],
    AB_MONTH[9], AB_MONTH[10], AB_MONTH[11]
);
pub const W_AMPM: [&[u32]; 2] = wide!(b"AM", b"PM");

/// The C locale's formats (NUL-terminated: they are used as format strings).
pub const C_D_T_FMT_Z: &CStr = c"%a %b %e %H:%M:%S %Y";
pub const C_D_FMT_Z: &CStr = c"%m/%d/%y";
pub const C_T_FMT_Z: &CStr = c"%H:%M:%S";
pub const C_T_FMT_AMPM_Z: &CStr = c"%I:%M:%S %p";
pub const C_D_T_FMT: &[u8] = C_D_T_FMT_Z.to_bytes_with_nul();
pub const C_D_FMT: &[u8] = C_D_FMT_Z.to_bytes_with_nul();
pub const C_T_FMT: &[u8] = C_T_FMT_Z.to_bytes_with_nul();
pub const C_T_FMT_AMPM: &[u8] = C_T_FMT_AMPM_Z.to_bytes_with_nul();

/// A format the strptime engine runs: a NUL-terminated string it can read in place (the C locale's built-in formats), or
/// a locale's item as a slice, which it runs on a NUL-terminated copy.
#[derive(Clone, Copy)]
pub enum Fmt {
    Z(ZStr<'static, u8>),
    S(&'static [u8]),
}

impl Fmt {
    /// True for the empty format.
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Fmt::Z(z) => z.at_end(),
            Fmt::S(s) => s.is_empty(),
        }
    }
}

/// A NUL-terminated constant without its NUL.
pub const fn no_nul(s: &'static [u8]) -> &'static [u8] {
    match s.split_last() {
        Some((0, rest)) => rest,
        _ => s,
    }
}

/// One era of the locale (`%EC`, `%Ey`, `%EY`).
#[derive(Clone, Copy)]
pub struct Era {
    pub direction: u32,
    pub offset: i32,
    pub start_date: [i32; 3],
    pub stop_date: [i32; 3],
    pub name: &'static [u8],
    pub format: &'static [u8],
    /// The same two as wide strings (what `wcsftime` uses).
    pub wname: &'static [u32],
    pub wformat: &'static [u32],
    /// +1 if the year number rises towards the future (like A.D.), -1 if towards the past.
    pub absolute_direction: i32,
}

fn date_le(a: &[i32; 3], b: &[i32; 3]) -> bool {
    a[0] < b[0] || (a[0] == b[0] && (a[1] < b[1] || (a[1] == b[1] && a[2] <= b[2])))
}

/// The C string at `p` in locale data, without its NUL.
///
/// # Safety
/// `p` points to a NUL-terminated string in locale data (which lives for ever).
#[inline]
unsafe fn cstr(p: *const u8) -> &'static [u8] {
    // SAFETY: forwarded contract.
    unsafe { rusty_libc_core::ffi::cstr_bytes_scalar(p) }
}

/// The wide string at `p` in locale data (4-aligned `u32` units up to a 0), without its terminator.
///
/// # Safety
/// `p` is 4-aligned and points to a 0-terminated `u32` string in locale data (which lives for ever).
unsafe fn wstr(p: *const u32) -> &'static [u32] {
    let mut n = 0;
    // SAFETY: the units up to and including the terminator are readable (caller's contract); the scan stops there.
    while unsafe { p.wrapping_add(n).read_unaligned() } != 0 {
        n += 1;
    }
    // SAFETY: `n` readable, initialised, aligned units that live for ever (caller's contract).
    unsafe { core::slice::from_raw_parts(p, n) }
}

/// The LC_TIME data of one locale.
#[derive(Clone, Copy)]
pub struct TimeLoc {
    d: Option<&'static CatData>,
    /// The LC_CTYPE data of the same locale (case mapping for the `^` flag).
    ct: Option<&'static CatData>,
}

impl TimeLoc {
    /// The locale in force for the calling thread.
    pub fn current() -> TimeLoc {
        let (d, ct) = locale::current2(locale::LC_TIME, locale::LC_CTYPE);
        Self::of(d, ct)
    }

    /// The locale of a `locale_t` argument (0 means the current one).
    ///
    /// # Safety
    /// `loc` is 0, LC_GLOBAL_LOCALE or a locale object (core's `locale::of_locale`).
    pub unsafe fn of_locale(loc: usize) -> TimeLoc {
        // SAFETY: forwarded contract.
        let d = unsafe { locale::of_locale(loc, locale::LC_TIME) };
        // SAFETY: forwarded contract.
        let ct = unsafe { locale::of_locale(loc, locale::LC_CTYPE) };
        Self::of(d, ct)
    }

    fn of(d: Option<&'static CatData>, ct: Option<&'static CatData>) -> TimeLoc {
        TimeLoc { d: d.filter(|d| d.flags() & F_PLAIN == 0), ct }
    }

    /// Upper-case a byte with the locale's case table.
    #[inline]
    pub fn toupper(&self, c: u8) -> u8 {
        if locale::ctype_special() { locale::toupper_in(self.ct, c as i32) as u8 } else { c.to_ascii_uppercase() }
    }

    /// Lower-case a byte with the locale's case table.
    #[inline]
    pub fn tolower(&self, c: u8) -> u8 {
        if locale::ctype_special() { locale::tolower_in(self.ct, c as i32) as u8 } else { c.to_ascii_lowercase() }
    }

    /// The C locale's data.
    pub const fn c() -> TimeLoc {
        TimeLoc { d: None, ct: None }
    }

    /// True if this is the C locale's data (built-in names and formats apply).
    pub fn is_c(&self) -> bool {
        self.d.is_none()
    }

    fn name(&self, base: usize, i: usize, c: &'static [&'static [u8]]) -> &'static [u8] {
        match self.d {
            None => c[i],
            Some(d) => d.bytes(base + i),
        }
    }
    pub fn abday(&self, i: usize) -> &'static [u8] {
        self.name(idx::ABDAY_1, i, &AB_WEEKDAY)
    }
    pub fn day(&self, i: usize) -> &'static [u8] {
        self.name(idx::DAY_1, i, &WEEKDAY)
    }
    pub fn abmon(&self, i: usize) -> &'static [u8] {
        self.name(idx::ABMON_1, i, &AB_MONTH)
    }
    pub fn mon(&self, i: usize) -> &'static [u8] {
        self.name(idx::MON_1, i, &MONTH)
    }
    pub fn altmon(&self, i: usize) -> &'static [u8] {
        self.name(idx::ALTMON_1, i, &MONTH)
    }
    pub fn abaltmon(&self, i: usize) -> &'static [u8] {
        self.name(idx::ABALTMON_1, i, &AB_MONTH)
    }
    /// "AM" or "PM" of the locale.
    pub fn ampm(&self, pm: bool) -> &'static [u8] {
        match self.d {
            None => {
                if pm {
                    b"PM"
                } else {
                    b"AM"
                }
            }
            Some(d) => d.bytes(if pm { idx::PM_STR } else { idx::AM_STR }),
        }
    }

    /// A format string item, without its NUL (the C locale's value if there is no data).
    fn fmt(&self, i: usize, c: &'static [u8]) -> &'static [u8] {
        match self.d {
            None => no_nul(c),
            Some(d) => d.bytes(i),
        }
    }
    /// A format item as the strptime engine runs it (in place for the C locale).
    fn fmt_z(&self, i: usize, c: &'static CStr) -> Fmt {
        match self.d {
            None => Fmt::Z(ZStr::from(c)),
            Some(d) => Fmt::S(d.bytes(i)),
        }
    }
    pub fn d_t_fmt_z(&self) -> Fmt {
        self.fmt_z(idx::D_T_FMT, C_D_T_FMT_Z)
    }
    pub fn d_fmt_z(&self) -> Fmt {
        self.fmt_z(idx::D_FMT, C_D_FMT_Z)
    }
    pub fn t_fmt_z(&self) -> Fmt {
        self.fmt_z(idx::T_FMT, C_T_FMT_Z)
    }
    pub fn t_fmt_ampm_z(&self) -> Fmt {
        self.fmt_z(idx::T_FMT_AMPM, C_T_FMT_AMPM_Z)
    }
    pub fn d_t_fmt(&self) -> &'static [u8] {
        self.fmt(idx::D_T_FMT, C_D_T_FMT)
    }
    pub fn d_fmt(&self) -> &'static [u8] {
        self.fmt(idx::D_FMT, C_D_FMT)
    }
    pub fn t_fmt(&self) -> &'static [u8] {
        self.fmt(idx::T_FMT, C_T_FMT)
    }
    pub fn t_fmt_ampm(&self) -> &'static [u8] {
        self.fmt(idx::T_FMT_AMPM, C_T_FMT_AMPM)
    }
    /// The era formats (empty in the C locale and most others).
    pub fn era_d_t_fmt(&self) -> &'static [u8] {
        self.fmt(idx::ERA_D_T_FMT, b"")
    }
    pub fn era_d_fmt(&self) -> &'static [u8] {
        self.fmt(idx::ERA_D_FMT, b"")
    }
    pub fn era_t_fmt(&self) -> &'static [u8] {
        self.fmt(idx::ERA_T_FMT, b"")
    }

    /// Number of eras.
    pub fn era_count(&self) -> usize {
        self.d.map_or(0, |d| d.word(idx::ERA_NUM_ENTRIES) as usize)
    }

    /// Era number `n` (parsed from glibc's binary table: per entry eight u32 (direction, offset,
    /// start date, stop date), the name and the format as C strings, padding to 4 bytes, the same
    /// two as wide strings).
    pub fn era(&self, n: usize) -> Option<Era> {
        if n >= self.era_count() {
            return None;
        }
        let mut p = self.d?.cstr(idx::ERA_ENTRIES);
        for k in 0..=n {
            let base = p;
            // SAFETY: `n` is below the entry count, so entry `k` exists in the table (inside the locale file, which lives
            // for ever) and starts with eight u32 words.
            let w = |i: usize| unsafe { p.wrapping_add(4 * i).cast::<u32>().read_unaligned() };
            let (direction, offset) = (w(0), w(1) as i32);
            let start_date = [w(2) as i32, w(3) as i32, w(4) as i32];
            let stop_date = [w(5) as i32, w(6) as i32, w(7) as i32];
            p = p.wrapping_add(32);
            // SAFETY: the name follows the words as a C string.
            let name = unsafe { cstr(p) };
            p = p.wrapping_add(name.len() + 1);
            // SAFETY: the format follows the name as a C string.
            let format = unsafe { cstr(p) };
            p = p.wrapping_add(format.len() + 1);
            let used = p as usize - base as usize;
            p = p.wrapping_add(3 - ((used + 3) & 3));
            // the wide copies of name and format
            let mut wide: [&'static [u32]; 2] = [&[], &[]];
            for slot in wide.iter_mut() {
                // SAFETY: after the padding to 4 bytes come the wide name and the wide format, 0-terminated.
                *slot = unsafe { wstr(p.cast::<u32>()) };
                p = p.wrapping_add(4 * (slot.len() + 1));
            }
            if k == n {
                let forward = date_le(&start_date, &stop_date);
                let plus = direction == u32::from(b'+');
                let absolute_direction = if forward == plus { 1 } else { -1 };
                return Some(Era { direction, offset, start_date, stop_date, name, format, wname: wide[0], wformat: wide[1], absolute_direction });
            }
        }
        None
    }

    /// The era containing the date of `tm` (year since 1900, month, day), like `_nl_get_era_entry`.
    pub fn era_for(&self, year: i32, mon: i32, mday: i32) -> Option<Era> {
        let t = [year, mon, mday];
        (0..self.era_count()).filter_map(|i| self.era(i)).find(|e| (date_le(&e.start_date, &t) && date_le(&t, &e.stop_date)) || (date_le(&e.stop_date, &t) && date_le(&t, &e.start_date)))
    }

    /// The locale's alternative representation of a number below 100 (`%Od` ...), if it has any.
    pub fn alt_digit(&self, n: u32) -> Option<&'static [u8]> {
        let d = self.d?;
        if n >= 100 || d.bytes(idx::ALT_DIGITS).is_empty() {
            return None;
        }
        let mut p = d.cstr(idx::ALT_DIGITS);
        for _ in 0..n {
            // SAFETY: the item is a list of 100 consecutive C strings and `n` < 100.
            p = p.wrapping_add(unsafe { cstr(p) }.len() + 1);
        }
        // SAFETY: as above.
        Some(unsafe { cstr(p) })
    }

    /// A wide string item of the locale data, without its terminator.
    /// (`None` in the C locale, which has no data: callers widen the narrow built-in value.)
    pub fn wide_item(&self, i: usize) -> Option<&'static [u32]> {
        let d = self.d?;
        if i >= d.nstrings() as usize {
            return Some(&[]);
        }
        // SAFETY: wide items are 0-terminated u32 strings, 4-aligned, in the locale data.
        Some(unsafe { wstr(d.cstr(i).cast::<u32>()) })
    }

    /// The wide alternative representation of `n` (the wide list parallels the narrow one), if the
    /// locale has any.
    pub fn walt_digit(&self, n: u32) -> Option<&'static [u32]> {
        if self.d.is_none() || n >= 100 {
            return None;
        }
        let first = self.wide_item(idx::WALT_DIGITS)?;
        if first.is_empty() {
            return None;
        }
        let mut p = first.as_ptr();
        for _ in 0..n {
            // SAFETY: the item is a list of 100 consecutive 0-terminated wide strings and `n` < 100.
            p = p.wrapping_add(unsafe { wstr(p) }.len() + 1);
        }
        // SAFETY: as above.
        Some(unsafe { wstr(p) })
    }

    /// `_nl_parse_alt_digit`: the longest alternative digit string at the cursor (bytes past the end read as NUL); returns
    /// its value (or -1) and moves `*rp` past it.
    pub fn parse_alt_digit(&self, rp: &mut ZStr<'_, u8>) -> i32 {
        // glibc tests the wide table's first character here
        if self.wide_item(idx::WALT_DIGITS).is_none_or(|w| w.is_empty()) {
            return -1;
        }
        let mut best: i32 = -1;
        let mut maxlen = 0;
        for cnt in 0..100u32 {
            let Some(dig) = self.alt_digit(cnt) else { return -1 };
            if dig.len() > maxlen && rp.starts_with(dig) {
                maxlen = dig.len();
                best = cnt as i32;
            }
        }
        if best != -1 {
            rp.bump_n(maxlen);
        }
        best
    }
}
