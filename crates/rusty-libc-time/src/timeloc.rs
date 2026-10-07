use rusty_libc_core::locale::{self, CatData, F_PLAIN, idx};

const WEEKDAY: [&[u8]; 7] = [b"Sunday", b"Monday", b"Tuesday", b"Wednesday", b"Thursday", b"Friday", b"Saturday"];
const AB_WEEKDAY: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTH: [&[u8]; 12] = [b"January", b"February", b"March", b"April", b"May", b"June", b"July", b"August", b"September", b"October", b"November", b"December"];
const AB_MONTH: [&[u8]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

pub const C_D_T_FMT: &[u8] = b"%a %b %e %H:%M:%S %Y\0";
pub const C_D_FMT: &[u8] = b"%m/%d/%y\0";
pub const C_T_FMT: &[u8] = b"%H:%M:%S\0";
pub const C_T_FMT_AMPM: &[u8] = b"%I:%M:%S %p\0";

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

#[derive(Clone, Copy)]
pub struct TimeLoc {
    d: *const CatData,
    ct: *const CatData,
}

impl TimeLoc {
    pub fn current() -> TimeLoc {
        Self::of(locale::current(locale::LC_TIME), locale::current(locale::LC_CTYPE))
    }

    pub fn of_locale(loc: usize) -> TimeLoc {
        Self::of(locale::of_locale(loc, locale::LC_TIME), locale::of_locale(loc, locale::LC_CTYPE))
    }

    fn of(d: *const CatData, ct: *const CatData) -> TimeLoc {
        let d = if d.is_null() || unsafe { (*d).flags } & F_PLAIN != 0 { core::ptr::null() } else { d };
        TimeLoc { d, ct }
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
        TimeLoc { d: core::ptr::null(), ct: core::ptr::null() }
    }

    pub fn is_c(&self) -> bool {
        self.d.is_null()
    }

    fn data(&self) -> &'static CatData {
        unsafe { &*self.d }
    }

    fn name(&self, base: usize, i: usize, c: &'static [&'static [u8]]) -> &'static [u8] {
        if self.d.is_null() { c[i] } else { self.data().bytes(base + i) }
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
        if self.d.is_null() {
            if pm { b"PM" } else { b"AM" }
        } else {
            self.data().bytes(if pm { idx::PM_STR } else { idx::AM_STR })
        }
    }

    fn fmt(&self, i: usize, c: &'static [u8]) -> *const u8 {
        if self.d.is_null() { c.as_ptr() } else { self.data().cstr(i) }
    }
    pub fn d_t_fmt(&self) -> *const u8 {
        self.fmt(idx::D_T_FMT, C_D_T_FMT)
    }
    pub fn d_fmt(&self) -> *const u8 {
        self.fmt(idx::D_FMT, C_D_FMT)
    }
    pub fn t_fmt(&self) -> *const u8 {
        self.fmt(idx::T_FMT, C_T_FMT)
    }
    pub fn t_fmt_ampm(&self) -> *const u8 {
        self.fmt(idx::T_FMT_AMPM, C_T_FMT_AMPM)
    }
    pub fn era_d_t_fmt(&self) -> *const u8 {
        self.fmt(idx::ERA_D_T_FMT, b"\0")
    }
    pub fn era_d_fmt(&self) -> *const u8 {
        self.fmt(idx::ERA_D_FMT, b"\0")
    }
    pub fn era_t_fmt(&self) -> *const u8 {
        self.fmt(idx::ERA_T_FMT, b"\0")
    }

    pub fn era_count(&self) -> usize {
        if self.d.is_null() { 0 } else { self.data().word(idx::ERA_NUM_ENTRIES) as usize }
    }

    pub fn era(&self, n: usize) -> Option<Era> {
        let cnt = self.era_count();
        if n >= cnt {
            return None;
        }
        let mut p = self.data().cstr(idx::ERA_ENTRIES);
        unsafe {
            for k in 0..=n {
                let base = p;
                let w = |i: usize| core::ptr::read_unaligned((p as *const u32).add(i));
                let (direction, offset) = (w(0), w(1) as i32);
                let start_date = [w(2) as i32, w(3) as i32, w(4) as i32];
                let stop_date = [w(5) as i32, w(6) as i32, w(7) as i32];
                p = p.add(32);
                let name = cstr(p);
                p = p.add(name.len() + 1);
                let format = cstr(p);
                p = p.add(format.len() + 1);
                let used = p.offset_from(base) as usize;
                p = p.add(3 - ((used + 3) & 3));
                let mut wide: [&'static [u32]; 2] = [&[], &[]];
                for slot in wide.iter_mut() {
                    let mut q = p as *const u32;
                    while core::ptr::read_unaligned(q) != 0 {
                        q = q.add(1);
                    }
                    *slot = core::slice::from_raw_parts(p as *const u32, q.offset_from(p as *const u32) as usize);
                    p = q.add(1) as *const u8;
                }
                if k == n {
                    let forward = date_le(&start_date, &stop_date);
                    let plus = direction == u32::from(b'+');
                    let absolute_direction = if forward == plus { 1 } else { -1 };
                    return Some(Era { direction, offset, start_date, stop_date, name, format, wname: wide[0], wformat: wide[1], absolute_direction });
                }
            }
        }
        None
    }

    pub fn era_for(&self, year: i32, mon: i32, mday: i32) -> Option<Era> {
        let t = [year, mon, mday];
        (0..self.era_count()).filter_map(|i| self.era(i)).find(|e| (date_le(&e.start_date, &t) && date_le(&t, &e.stop_date)) || (date_le(&e.stop_date, &t) && date_le(&t, &e.start_date)))
    }

    pub fn alt_digit(&self, n: u32) -> Option<&'static [u8]> {
        if self.d.is_null() || n >= 100 {
            return None;
        }
        let d = self.data();
        if unsafe { *d.cstr(idx::ALT_DIGITS) } == 0 {
            return None;
        }
        let mut p = d.cstr(idx::ALT_DIGITS);
        unsafe {
            for _ in 0..n {
                p = p.add(cstr(p).len() + 1);
            }
            Some(cstr(p))
        }
    }

    pub fn wide_item(&self, i: usize) -> Option<(*const u32, usize)> {
        if self.d.is_null() {
            return None;
        }
        unsafe {
            if i >= self.data().nstrings as usize {
                static ZERO: u32 = 0;
                return Some((&ZERO, 0));
            }
            let p = self.data().cstr(i) as *const u32;
            let mut n = 0;
            while core::ptr::read_unaligned(p.add(n)) != 0 {
                n += 1;
            }
            Some((p, n))
        }
    }

    pub fn walt_digit(&self, n: u32) -> Option<(*const u32, usize)> {
        if self.d.is_null() || n >= 100 {
            return None;
        }
        let (mut p, first) = self.wide_item(idx::WALT_DIGITS)?;
        if first == 0 {
            return None;
        }
        unsafe {
            for _ in 0..n {
                let mut k = 0;
                while core::ptr::read_unaligned(p.add(k)) != 0 {
                    k += 1;
                }
                p = p.add(k + 1);
            }
            let mut k = 0;
            while core::ptr::read_unaligned(p.add(k)) != 0 {
                k += 1;
            }
            Some((p, k))
        }
    }

    pub unsafe fn parse_alt_digit(&self, rp: &mut *const u8) -> i32 {
        if self.d.is_null() || unsafe { core::ptr::read_unaligned(self.data().cstr(idx::WALT_DIGITS) as *const u32) } == 0 {
            return -1;
        }
        let mut best: i32 = -1;
        let mut maxlen = 0;
        for cnt in 0..100u32 {
            let Some(dig) = self.alt_digit(cnt) else { return -1 };
            if dig.len() > maxlen && dig.iter().enumerate().all(|(k, &c)| unsafe { *rp.add(k) } == c) {
                maxlen = dig.len();
                best = cnt as i32;
            }
        }
        if best != -1 {
            *rp = unsafe { rp.add(maxlen) };
        }
        best
    }
}

fn cstr(p: *const u8) -> &'static [u8] {
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        core::slice::from_raw_parts(p, n)
    }
}
