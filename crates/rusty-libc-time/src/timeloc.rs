use core::ffi::CStr;
use rusty_libc_core::locale::{self, CatData, F_PLAIN, idx};
use rusty_libc_stdlib::zstr::ZStr;

const WEEKDAY: [&[u8]; 7] = [b"Sunday", b"Monday", b"Tuesday", b"Wednesday", b"Thursday", b"Friday", b"Saturday"];
const AB_WEEKDAY: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTH: [&[u8]; 12] = [b"January", b"February", b"March", b"April", b"May", b"June", b"July", b"August", b"September", b"October", b"November", b"December"];
const AB_MONTH: [&[u8]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

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

pub const C_D_T_FMT_Z: &CStr = c"%a %b %e %H:%M:%S %Y";
pub const C_D_FMT_Z: &CStr = c"%m/%d/%y";
pub const C_T_FMT_Z: &CStr = c"%H:%M:%S";
pub const C_T_FMT_AMPM_Z: &CStr = c"%I:%M:%S %p";
pub const C_D_T_FMT: &[u8] = C_D_T_FMT_Z.to_bytes_with_nul();
pub const C_D_FMT: &[u8] = C_D_FMT_Z.to_bytes_with_nul();
pub const C_T_FMT: &[u8] = C_T_FMT_Z.to_bytes_with_nul();
pub const C_T_FMT_AMPM: &[u8] = C_T_FMT_AMPM_Z.to_bytes_with_nul();

#[derive(Clone, Copy)]
pub enum Fmt {
    Z(ZStr<'static, u8>),
    S(&'static [u8]),
}

impl Fmt {
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Fmt::Z(z) => z.at_end(),
            Fmt::S(s) => s.is_empty(),
        }
    }
}

pub const fn no_nul(s: &'static [u8]) -> &'static [u8] {
    match s.split_last() {
        Some((0, rest)) => rest,
        _ => s,
    }
}

#[derive(Clone, Copy)]
pub struct Era {
    pub direction: u32,
    pub offset: i32,
    pub start_date: [i32; 3],
    pub stop_date: [i32; 3],
    pub name: &'static [u8],
    pub format: &'static [u8],
    pub wname: &'static [u32],
    pub wformat: &'static [u32],
    pub absolute_direction: i32,
}

fn date_le(a: &[i32; 3], b: &[i32; 3]) -> bool {
    a[0] < b[0] || (a[0] == b[0] && (a[1] < b[1] || (a[1] == b[1] && a[2] <= b[2])))
}

#[inline]
unsafe fn cstr(p: *const u8) -> &'static [u8] {
    unsafe { rusty_libc_core::ffi::cstr_bytes_scalar(p) }
}

unsafe fn wstr(p: *const u32) -> &'static [u32] {
    let mut n = 0;
    while unsafe { p.wrapping_add(n).read_unaligned() } != 0 {
        n += 1;
    }
    unsafe { core::slice::from_raw_parts(p, n) }
}

#[derive(Clone, Copy)]
pub struct TimeLoc {
    d: Option<&'static CatData>,
    ct: Option<&'static CatData>,
}

impl TimeLoc {
    pub fn current() -> TimeLoc {
        let (d, ct) = locale::current2(locale::LC_TIME, locale::LC_CTYPE);
        Self::of(d, ct)
    }

    pub unsafe fn of_locale(loc: usize) -> TimeLoc {
        let d = unsafe { locale::of_locale(loc, locale::LC_TIME) };
        let ct = unsafe { locale::of_locale(loc, locale::LC_CTYPE) };
        Self::of(d, ct)
    }

    fn of(d: Option<&'static CatData>, ct: Option<&'static CatData>) -> TimeLoc {
        TimeLoc { d: d.filter(|d| d.flags() & F_PLAIN == 0), ct }
    }

    #[inline]
    pub fn toupper(&self, c: u8) -> u8 {
        if locale::ctype_special() { locale::toupper_in(self.ct, c as i32) as u8 } else { c.to_ascii_uppercase() }
    }

    #[inline]
    pub fn tolower(&self, c: u8) -> u8 {
        if locale::ctype_special() { locale::tolower_in(self.ct, c as i32) as u8 } else { c.to_ascii_lowercase() }
    }

    pub const fn c() -> TimeLoc {
        TimeLoc { d: None, ct: None }
    }

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

    fn fmt(&self, i: usize, c: &'static [u8]) -> &'static [u8] {
        match self.d {
            None => no_nul(c),
            Some(d) => d.bytes(i),
        }
    }
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
    pub fn era_d_t_fmt(&self) -> &'static [u8] {
        self.fmt(idx::ERA_D_T_FMT, b"")
    }
    pub fn era_d_fmt(&self) -> &'static [u8] {
        self.fmt(idx::ERA_D_FMT, b"")
    }
    pub fn era_t_fmt(&self) -> &'static [u8] {
        self.fmt(idx::ERA_T_FMT, b"")
    }

    pub fn era_count(&self) -> usize {
        self.d.map_or(0, |d| d.word(idx::ERA_NUM_ENTRIES) as usize)
    }

    pub fn era(&self, n: usize) -> Option<Era> {
        if n >= self.era_count() {
            return None;
        }
        let mut p = self.d?.cstr(idx::ERA_ENTRIES);
        for k in 0..=n {
            let base = p;
            let w = |i: usize| unsafe { p.wrapping_add(4 * i).cast::<u32>().read_unaligned() };
            let (direction, offset) = (w(0), w(1) as i32);
            let start_date = [w(2) as i32, w(3) as i32, w(4) as i32];
            let stop_date = [w(5) as i32, w(6) as i32, w(7) as i32];
            p = p.wrapping_add(32);
            let name = unsafe { cstr(p) };
            p = p.wrapping_add(name.len() + 1);
            let format = unsafe { cstr(p) };
            p = p.wrapping_add(format.len() + 1);
            let used = p as usize - base as usize;
            p = p.wrapping_add(3 - ((used + 3) & 3));
            let mut wide: [&'static [u32]; 2] = [&[], &[]];
            for slot in wide.iter_mut() {
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

    pub fn era_for(&self, year: i32, mon: i32, mday: i32) -> Option<Era> {
        let t = [year, mon, mday];
        (0..self.era_count()).filter_map(|i| self.era(i)).find(|e| (date_le(&e.start_date, &t) && date_le(&t, &e.stop_date)) || (date_le(&e.stop_date, &t) && date_le(&t, &e.start_date)))
    }

    pub fn alt_digit(&self, n: u32) -> Option<&'static [u8]> {
        let d = self.d?;
        if n >= 100 || d.bytes(idx::ALT_DIGITS).is_empty() {
            return None;
        }
        let mut p = d.cstr(idx::ALT_DIGITS);
        for _ in 0..n {
            p = p.wrapping_add(unsafe { cstr(p) }.len() + 1);
        }
        Some(unsafe { cstr(p) })
    }

    pub fn wide_item(&self, i: usize) -> Option<&'static [u32]> {
        let d = self.d?;
        if i >= d.nstrings() as usize {
            return Some(&[]);
        }
        Some(unsafe { wstr(d.cstr(i).cast::<u32>()) })
    }

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
            p = p.wrapping_add(unsafe { wstr(p) }.len() + 1);
        }
        Some(unsafe { wstr(p) })
    }

    pub fn parse_alt_digit(&self, rp: &mut ZStr<'_, u8>) -> i32 {
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
