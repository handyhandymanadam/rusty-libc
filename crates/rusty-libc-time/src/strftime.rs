use crate::calendar::{self, Tm};
use crate::clock::LocaleT;
use crate::timeloc::{self, TimeLoc};
use crate::tz;
use core::ffi::{c_char, c_int};
use rusty_libc_core::{env, errno, syscall};

const EINVAL: i32 = 22;


fn isleap(y: i32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

unsafe fn cstrlen(s: *const u8) -> usize {
    unsafe {
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        n
    }
}

fn iso_week_days(yday: i32, wday: i32) -> i32 {
    let big_enough_multiple_of_7 = (366 / 7 + 2) * 7;
    yday - (yday - wday + 4 + big_enough_multiple_of_7) % 7 + 4 - 1
}

#[inline(always)]
unsafe fn copy_units<C>(src: *const C, dst: *mut C, n: usize) {
    unsafe {
        if size_of::<C>() == 1 && n <= 16 {
            let (s, d) = (src as *const u8, dst as *mut u8);
            if n >= 8 {
                let (a, b) = ((s as *const u64).read_unaligned(), (s.add(n - 8) as *const u64).read_unaligned());
                (d as *mut u64).write_unaligned(a);
                (d.add(n - 8) as *mut u64).write_unaligned(b);
            } else if n >= 4 {
                let (a, b) = ((s as *const u32).read_unaligned(), (s.add(n - 4) as *const u32).read_unaligned());
                (d as *mut u32).write_unaligned(a);
                (d.add(n - 4) as *mut u32).write_unaligned(b);
            } else {
                for k in 0..n {
                    *d.add(k) = *s.add(k);
                }
            }
        } else {
            core::ptr::copy_nonoverlapping(src, dst, n);
        }
    }
}

#[inline(never)]
fn tm_number(fc: u8, tp: &Tm) -> i32 {
    match fc {
        b'C' => {
            let year = tp.tm_year.wrapping_add(1900);
            year / 100 - (year % 100 < 0) as i32
        }
        b'u' => (tp.tm_wday - 1 + 7) % 7 + 1,
        b'U' => (tp.tm_yday - tp.tm_wday + 7) / 7,
        b'W' => (tp.tm_yday - (tp.tm_wday - 1 + 7) % 7 + 7) / 7,
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

#[derive(Clone, Copy)]
enum Next<C> {
    Switch,
    Number(i32, i32, bool),
    Sub(*const C),
    Bad,
}

#[derive(Clone, Copy)]
pub struct Wc {
    pub up: fn(u32, usize) -> u32,
    pub low: fn(u32, usize) -> u32,
    pub loc: usize,
}

fn same(c: u32, _loc: usize) -> u32 {
    c
}

const NARROW: Wc = Wc { up: same, low: same, loc: 0 };

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
    Lit(&'static [u8]),
}

pub trait Ch: Copy + 'static {
    const WIDE: bool;
    fn asc(self) -> u8;
    fn from_u8(b: u8) -> Self;
    fn lower(self, tl: &TimeLoc, wc: Wc) -> Self;
    fn upper(self, tl: &TimeLoc, wc: Wc) -> Self;
    fn text(tl: &TimeLoc, it: It, tmp: &mut [Self; 96]) -> (*const Self, usize);
}

#[inline(never)]
fn narrow_text(tl: &TimeLoc, it: It) -> (*const u8, usize) {
    let cs = |p: *const u8| -> (*const u8, usize) { (p, unsafe { cstrlen(p) }) };
    let sl: &[u8] = match it {
        It::AbDay(i) => tl.abday(i),
        It::Day(i) => tl.day(i),
        It::AbMon(i) => tl.abmon(i),
        It::Mon(i) => tl.mon(i),
        It::AltMon(i) => tl.altmon(i),
        It::AbAltMon(i) => tl.abaltmon(i),
        It::AmPm(pm) => tl.ampm(pm),
        It::DTFmt => return cs(tl.d_t_fmt()),
        It::DFmt => return cs(tl.d_fmt()),
        It::TFmt => return cs(tl.t_fmt()),
        It::TFmtAmpm => return cs(tl.t_fmt_ampm()),
        It::EraDTFmt => return cs(tl.era_d_t_fmt()),
        It::EraDFmt => return cs(tl.era_d_fmt()),
        It::EraTFmt => return cs(tl.era_t_fmt()),
        It::EraName(e) => e.name,
        It::EraFormat(e) => e.format,
        It::AltDigit(n) => tl.alt_digit(n).unwrap_or(b""),
        It::Lit(l) => &l[..l.len() - 1],
    };
    (sl.as_ptr(), sl.len())
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
    fn text(tl: &TimeLoc, it: It, _tmp: &mut [u8; 96]) -> (*const u8, usize) {
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
                return (sl.as_ptr(), sl.len());
            }
        }
        narrow_text(tl, it)
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
        (wc.low)(self, wc.loc)
    }
    fn upper(self, _tl: &TimeLoc, wc: Wc) -> u32 {
        (wc.up)(self, wc.loc)
    }
    fn text(tl: &TimeLoc, it: It, tmp: &mut [u32; 96]) -> (*const u32, usize) {
        use rusty_libc_core::locale::idx;
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
            return r;
        }
        match it {
            It::EraName(e) => return (e.wname.as_ptr(), e.wname.len()),
            It::EraFormat(e) => return (e.wformat.as_ptr(), e.wformat.len()),
            It::AltDigit(n) => return tl.walt_digit(n).unwrap_or((tmp.as_ptr(), 0)),
            _ => {}
        }
        let (p, n) = narrow_text(tl, it);
        let n = n.min(tmp.len() - 1);
        for (k, t) in tmp.iter_mut().enumerate().take(n) {
            *t = u32::from(unsafe { *p.add(k) });
        }
        tmp[n] = 0;
        (tmp.as_ptr(), n)
    }
}

unsafe fn fill<C: Ch>(p: *mut C, b: u8, n: usize) {
    unsafe {
        for k in 0..n {
            *p.add(k) = C::from_u8(b);
        }
    }
}

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

#[inline(always)]
unsafe fn rv<T: Copy>(r: &T) -> T {
    unsafe { core::ptr::read_volatile(r) }
}

#[allow(clippy::too_many_arguments)]
unsafe fn strftime_internal<C: Ch>(s: *mut C, maxsize: usize, format: *const C, tp_ref: &Tm, tzset_called: &mut bool, tl: &TimeLoc, wc: Wc, yr_spec: u8) -> usize {
    unsafe {
        let mut yr_spec = yr_spec;
        let tp: *const Tm = tp_ref;
        let mut zone: *const u8 = rv(&(*tp).tm_zone).cast();
        macro_rules! hour12 {
            () => {{
                let h = rv(&(*tp).tm_hour);
                if h > 12 { h - 12 } else if h == 0 { 12 } else { h }
            }};
        }
        let mut i = 0usize;
        let mut p = s;
        let mut f = format;
        let mut buf = [0u8; 24];
        let mut tmp = [C::from_u8(0); 96];

        while (*f).asc() != 0 {
            let mut pad: u8 = 0;
            let mut width: i32 = -1;
            let mut to_lowcase = false;
            let mut to_uppcase = false;
            let mut change_case = false;

            macro_rules! add {
                ($n:expr, |$q:ident| $body:expr) => {{
                    let n: i32 = $n as i32;
                    let delta = width - n;
                    let incr = n + if delta > 0 { delta } else { 0 };
                    if (incr as usize) >= maxsize.wrapping_sub(i) {
                        return 0;
                    }
                    if !p.is_null() {
                        if delta > 0 {
                            fill(p, if pad == b'0' { b'0' } else { b' ' }, delta as usize);
                            p = p.add(delta as usize);
                        }
                        let $q = p;
                        $body;
                        p = p.add(n as usize);
                    }
                    i += incr as usize;
                }};
            }
            macro_rules! cpy {
                ($n:expr, $src:expr) => {{
                    let src: *const C = $src;
                    let nn: usize = $n;
                    add!(nn, |q| {
                        if !to_lowcase && !to_uppcase {
                            copy_units(src, q, nn);
                        } else {
                            for k in 0..nn {
                                let c = *src.add(k);
                                *q.add(k) = if to_lowcase { c.lower(tl, wc) } else { c.upper(tl, wc) };
                            }
                        }
                    });
                }};
            }
            macro_rules! cpyb {
                ($n:expr, $src:expr) => {{
                    let src: *const u8 = $src;
                    let nn: usize = $n;
                    add!(nn, |q| {
                        if !to_lowcase && !to_uppcase {
                            if size_of::<C>() == 1 {
                                copy_units(src as *const C, q, nn);
                            } else {
                                for k in 0..nn {
                                    *q.add(k) = C::from_u8(*src.add(k));
                                }
                            }
                        } else {
                            for k in 0..nn {
                                let c = C::from_u8(*src.add(k));
                                *q.add(k) = if to_lowcase { c.lower(tl, wc) } else { c.upper(tl, wc) };
                            }
                        }
                    });
                }};
            }

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
                                if (padding as usize) >= maxsize.wrapping_sub(i) {
                                    return 0;
                                }
                                if !p.is_null() {
                                    fill(p, b' ', padding as usize);
                                    p = p.add(padding as usize);
                                }
                                i += padding as usize;
                                width = if width > padding { width - padding } else { 0 };
                            } else {
                                if (digits as usize) >= maxsize.wrapping_sub(i) {
                                    return 0;
                                }
                                if negative {
                                    bp += 1;
                                    if !p.is_null() {
                                        *p = C::from_u8(b'-');
                                        p = p.add(1);
                                    }
                                    i += 1;
                                }
                                if !p.is_null() {
                                    fill(p, b'0', padding as usize);
                                    p = p.add(padding as usize);
                                }
                                i += padding as usize;
                                width = 0;
                            }
                        }
                    }
                    let len = $buf.len() - bp;
                    cpyb!(len, $buf.as_ptr().add(bp));
                }};
            }

            if (*f).asc() != b'%' {
                let mut run = 1usize;
                loop {
                    let a = (*f.add(run)).asc();
                    if a == b'%' || a == 0 {
                        break;
                    }
                    run += 1;
                }
                if run >= maxsize.wrapping_sub(i) {
                    run = 1;
                    if run >= maxsize.wrapping_sub(i) {
                        return 0;
                    }
                }
                if !p.is_null() {
                    copy_units(f, p, run);
                    p = p.add(run);
                }
                i += run;
                f = f.add(run);
                continue;
            }
            loop {
                f = f.add(1);
                match (*f).asc() {
                    b'_' | b'-' | b'0' => {
                        pad = (*f).asc();
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
            if (*f).asc().is_ascii_digit() {
                width = 0;
                while (*f).asc().is_ascii_digit() {
                    let d = ((*f).asc() - b'0') as i32;
                    if width > i32::MAX / 10 || (width == i32::MAX / 10 && d > i32::MAX % 10) {
                        width = i32::MAX;
                    } else {
                        width = width * 10 + d;
                    }
                    f = f.add(1);
                }
            }
            let modifier = if (*f).asc() == b'E' || (*f).asc() == b'O' {
                let m = (*f).asc();
                f = f.add(1);
                m
            } else {
                0
            };
            let format_char = (*f).asc();
            let mut next: Next<C> = Next::Switch;

            'dispatch: loop {
                match next {
                    Next::Switch => {
                        macro_rules! number {
                            ($d:expr, $v:expr) => {{
                                let d: i32 = $d;
                                next = Next::Number(d, $v, false);
                                continue 'dispatch;
                            }};
                        }
                        macro_rules! number_sp {
                            ($d:expr, $v:expr) => {{
                                let d: i32 = $d;
                                next = Next::Number(d, $v, true);
                                continue 'dispatch;
                            }};
                        }
                        macro_rules! bad {
                            () => {{
                                next = Next::Bad;
                                continue 'dispatch;
                            }};
                        }
                        match format_char {
                            b'%' => {
                                if modifier != 0 {
                                    bad!();
                                }
                                add!(1, |q| *q = C::from_u8(b'%'));
                            }
                            b'a' => {
                                if modifier != 0 {
                                    bad!();
                                }
                                if change_case {
                                    to_uppcase = true;
                                    to_lowcase = false;
                                }
                                let (np, nl) = if (0..=6).contains(&rv(&(*tp).tm_wday)) { C::text(tl, It::AbDay(rv(&(*tp).tm_wday) as usize), &mut tmp) } else { C::text(tl, It::Lit(b"?\0"), &mut tmp) };
                                cpy!(nl, np);
                            }
                            b'A' => {
                                if modifier != 0 {
                                    bad!();
                                }
                                if change_case {
                                    to_uppcase = true;
                                    to_lowcase = false;
                                }
                                let (np, nl) = if (0..=6).contains(&rv(&(*tp).tm_wday)) { C::text(tl, It::Day(rv(&(*tp).tm_wday) as usize), &mut tmp) } else { C::text(tl, It::Lit(b"?\0"), &mut tmp) };
                                cpy!(nl, np);
                            }
                            b'b' | b'h' => {
                                if change_case {
                                    to_uppcase = true;
                                    to_lowcase = false;
                                }
                                if modifier == b'E' {
                                    bad!();
                                }
                                let (np, nl) = if !(0..=11).contains(&rv(&(*tp).tm_mon)) {
                                    C::text(tl, It::Lit(b"?\0"), &mut tmp)
                                } else if modifier == b'O' {
                                    C::text(tl, It::AbAltMon(rv(&(*tp).tm_mon) as usize), &mut tmp)
                                } else {
                                    C::text(tl, It::AbMon(rv(&(*tp).tm_mon) as usize), &mut tmp)
                                };
                                cpy!(nl, np);
                            }
                            b'B' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                if change_case {
                                    to_uppcase = true;
                                    to_lowcase = false;
                                }
                                let (np, nl) = if !(0..=11).contains(&rv(&(*tp).tm_mon)) {
                                    C::text(tl, It::Lit(b"?\0"), &mut tmp)
                                } else if modifier == b'O' {
                                    C::text(tl, It::AltMon(rv(&(*tp).tm_mon) as usize), &mut tmp)
                                } else {
                                    C::text(tl, It::Mon(rv(&(*tp).tm_mon) as usize), &mut tmp)
                                };
                                cpy!(nl, np);
                            }
                            b'c' => {
                                if modifier == b'O' {
                                    bad!();
                                }
                                let e = C::text(tl, It::EraDTFmt, &mut tmp);
                                let sub = if modifier == b'E' && e.1 != 0 { e.0 } else { C::text(tl, It::DTFmt, &mut tmp).0 };
                                next = Next::Sub(sub);
                                continue 'dispatch;
                            }
                            b'C' => {
                                if modifier == b'E'
                                    && let Some(era) = tl.era_for(rv(&(*tp).tm_year), rv(&(*tp).tm_mon), rv(&(*tp).tm_mday))
                                {
                                    let (np, nl) = C::text(tl, It::EraName(&era), &mut tmp);
                                    cpy!(nl, np);
                                    break 'dispatch;
                                }
                                number!(1, tm_number(b'C', &*tp));
                            }
                            b'x' => {
                                if modifier == b'O' {
                                    bad!();
                                }
                                let e = C::text(tl, It::EraDFmt, &mut tmp);
                                let sub = if modifier == b'E' && e.1 != 0 { e.0 } else { C::text(tl, It::DFmt, &mut tmp).0 };
                                next = Next::Sub(sub);
                                continue 'dispatch;
                            }
                            b'D' => {
                                if modifier != 0 {
                                    bad!();
                                }
                                next = Next::Sub(C::text(tl, It::Lit(b"%m/%d/%y\0"), &mut tmp).0);
                                continue 'dispatch;
                            }
                            b'd' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number!(2, rv(&(*tp).tm_mday));
                            }
                            b'e' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number_sp!(2, rv(&(*tp).tm_mday));
                            }
                            b'F' => {
                                if modifier != 0 {
                                    bad!();
                                }
                                next = Next::Sub(C::text(tl, It::Lit(b"%Y-%m-%d\0"), &mut tmp).0);
                                continue 'dispatch;
                            }
                            b'H' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number!(2, rv(&(*tp).tm_hour));
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
                                number_sp!(2, rv(&(*tp).tm_hour));
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
                                number!(3, 1i32.wrapping_add(rv(&(*tp).tm_yday)));
                            }
                            b'M' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number!(2, rv(&(*tp).tm_min));
                            }
                            b'm' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number!(2, rv(&(*tp).tm_mon).wrapping_add(1));
                            }
                            b'n' => {
                                add!(1, |q| *q = C::from_u8(b'\n'));
                            }
                            b'P' | b'p' => {
                                if format_char == b'P' {
                                    to_lowcase = true;
                                }
                                if change_case {
                                    to_uppcase = false;
                                    to_lowcase = true;
                                }
                                let (np, nl) = C::text(tl, It::AmPm(rv(&(*tp).tm_hour) > 11), &mut tmp);
                                cpy!(nl, np);
                            }
                            b'R' => {
                                next = Next::Sub(C::text(tl, It::Lit(b"%H:%M\0"), &mut tmp).0);
                                continue 'dispatch;
                            }
                            b'r' => {
                                let e = C::text(tl, It::TFmtAmpm, &mut tmp);
                                next = Next::Sub(if e.1 == 0 { C::text(tl, It::Lit(timeloc::C_T_FMT_AMPM), &mut tmp).0 } else { e.0 });
                                continue 'dispatch;
                            }
                            b'S' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number!(2, rv(&(*tp).tm_sec));
                            }
                            b's' => {
                                let mut ltm = *tp;
                                let t = calendar::mktime(&mut ltm);
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
                                let e = C::text(tl, It::EraTFmt, &mut tmp);
                                let sub = if modifier == b'E' && e.1 != 0 { e.0 } else { C::text(tl, It::TFmt, &mut tmp).0 };
                                next = Next::Sub(sub);
                                continue 'dispatch;
                            }
                            b'T' => {
                                next = Next::Sub(C::text(tl, It::Lit(b"%H:%M:%S\0"), &mut tmp).0);
                                continue 'dispatch;
                            }
                            b't' => {
                                add!(1, |q| *q = C::from_u8(b'\t'));
                            }
                            b'u' => {
                                number!(1, tm_number(b'u', &*tp));
                            }
                            b'U' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number!(2, tm_number(b'U', &*tp));
                            }
                            b'V' | b'g' | b'G' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                match format_char {
                                    b'g' => number!(2, tm_number(b'g', &*tp)),
                                    b'G' => number!(1, tm_number(b'G', &*tp)),
                                    _ => number!(2, tm_number(b'V', &*tp)),
                                }
                            }
                            b'W' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number!(2, tm_number(b'W', &*tp));
                            }
                            b'w' => {
                                if modifier == b'E' {
                                    bad!();
                                }
                                number!(1, rv(&(*tp).tm_wday));
                            }
                            b'Y' => {
                                if modifier == b'E'
                                    && let Some(era) = tl.era_for(rv(&(*tp).tm_year), rv(&(*tp).tm_mon), rv(&(*tp).tm_mday))
                                {
                                    if pad != 0 {
                                        yr_spec = pad;
                                    }
                                    next = Next::Sub(C::text(tl, It::EraFormat(&era), &mut tmp).0);
                                    continue 'dispatch;
                                }
                                if modifier == b'O' {
                                    bad!();
                                }
                                number!(1, rv(&(*tp).tm_year).wrapping_add(1900));
                            }
                            b'y' => {
                                if modifier == b'E'
                                    && let Some(era) = tl.era_for(rv(&(*tp).tm_year), rv(&(*tp).tm_mon), rv(&(*tp).tm_mday))
                                {
                                    let delta = rv(&(*tp).tm_year) - era.start_date[0];
                                    if yr_spec != 0 {
                                        pad = yr_spec;
                                    }
                                    number!(2, era.offset + delta * era.absolute_direction);
                                }
                                number!(2, tm_number(b'y', &*tp));
                            }
                            b'Z' => {
                                if change_case && !C::WIDE {
                                    to_uppcase = false;
                                    to_lowcase = true;
                                }
                                if C::WIDE && pad == b'-' {
                                    width = -1;
                                }
                                if (zone.is_null() || *zone == 0) && rv(&(*tp).tm_isdst) >= 0 {
                                    if !*tzset_called {
                                        tz::tzset();
                                        *tzset_called = true;
                                    }
                                    zone = if rv(&(*tp).tm_isdst) <= 1 { tz::tzname_ptr(rv(&(*tp).tm_isdst) as usize).cast() } else { c"?".as_ptr().cast() };
                                }
                                if zone.is_null() {
                                    zone = c"".as_ptr().cast();
                                }
                                cpyb!(cstrlen(zone), zone);
                            }
                            b'z' => {
                                if rv(&(*tp).tm_isdst) < 0 {
                                } else {
                                    let mut diff = rv(&(*tp).tm_gmtoff) as i32;
                                    if diff < 0 {
                                        add!(1, |q| *q = C::from_u8(b'-'));
                                        diff = diff.wrapping_neg();
                                    } else {
                                        add!(1, |q| *q = C::from_u8(b'+'));
                                    }
                                    diff /= 60;
                                    number!(4, (diff / 60) * 100 + diff % 60);
                                }
                            }
                            0 => {
                                f = f.sub(1);
                                bad!();
                            }
                            _ => {
                                bad!();
                            }
                        }
                        break 'dispatch;
                    }
                    Next::Number(digits, number_value, spacepad) => {
                        let digits = if digits > width { digits } else { width };
                        if spacepad && pad != b'0' && pad != b'-' {
                            pad = b'_';
                        }
                        if modifier == b'O' && number_value >= 0 {
                            let (cp, cl) = C::text(tl, It::AltDigit(number_value as u32), &mut tmp);
                            if cl != 0 {
                                cpy!(cl, cp);
                                break 'dispatch;
                            }
                        }
                        let mut bp = buf.len();
                        let negative = number_value < 0;
                        let mut u = number_value as u32;
                        if negative {
                            u = u.wrapping_neg();
                        }
                        while u >= 100 {
                            let r = (u % 100) as usize;
                            u /= 100;
                            bp -= 2;
                            buf[bp] = DIGIT_PAIRS[2 * r];
                            buf[bp + 1] = DIGIT_PAIRS[2 * r + 1];
                        }
                        if u >= 10 {
                            bp -= 2;
                            buf[bp] = DIGIT_PAIRS[2 * u as usize];
                            buf[bp + 1] = DIGIT_PAIRS[2 * u as usize + 1];
                        } else {
                            bp -= 1;
                            buf[bp] = u as u8 + b'0';
                        }
                        emit_number!(buf, bp, negative, digits);
                        break 'dispatch;
                    }
                    Next::Sub(subfmt) => {
                        let old_start = p;
                        let mut scratch = core::mem::MaybeUninit::<[C; 128]>::uninit();
                        let sp = scratch.as_mut_ptr() as *mut C;
                        let mut tz2 = *tzset_called;
                        let r = strftime_internal(sp, 128, subfmt, tp_ref, &mut tz2, tl, wc, yr_spec);
                        if r != 0 {
                            *tzset_called = tz2;
                            add!(r, |q| {
                                copy_units(sp as *const C, q, r);
                                *q.add(r) = C::from_u8(0);
                            });
                        } else {
                            let mut tz2 = *tzset_called;
                            let len = strftime_internal(core::ptr::null_mut(), usize::MAX, subfmt, tp_ref, &mut tz2, tl, wc, yr_spec);
                            *tzset_called = tz2;
                            add!(len, |q| {
                                let r = strftime_internal(q, maxsize.wrapping_sub(i), subfmt, tp_ref, tzset_called, tl, wc, yr_spec);
                                let _ = r;
                            });
                        }
                        if to_uppcase && !old_start.is_null() {
                            let mut q = old_start;
                            while q < p {
                                *q = (*q).upper(tl, wc);
                                q = q.add(1);
                            }
                        }
                        break 'dispatch;
                    }
                    Next::Bad => {
                        let mut flen = 1usize;
                        while (*f.sub(flen - 1)).asc() != b'%' {
                            flen += 1;
                        }
                        cpy!(flen, f.sub(flen - 1));
                        break 'dispatch;
                    }
                }
            }
            f = f.add(1);

        }
        if !p.is_null() && maxsize != 0 {
            *p = C::from_u8(0);
        }
        i
    }
}


#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strftime(s: *mut c_char, maxsize: usize, format: *const c_char, tp: *const Tm) -> usize {
    unsafe {
        let mut tzset_called = false;
        strftime_internal::<u8>(s.cast(), maxsize, format.cast(), &*tp, &mut tzset_called, &TimeLoc::current(), NARROW, 0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strftime_l(s: *mut c_char, maxsize: usize, format: *const c_char, tp: *const Tm, loc: LocaleT) -> usize {
    unsafe {
        let mut tzset_called = false;
        strftime_internal::<u8>(s.cast(), maxsize, format.cast(), &*tp, &mut tzset_called, &TimeLoc::of_locale(loc as usize), NARROW, 0)
    }
}

pub unsafe fn wcsftime_with(s: *mut u32, maxsize: usize, format: *const u32, tp: *const Tm, loc: usize, wc: Wc) -> usize {
    unsafe {
        let mut tzset_called = false;
        let tl = if loc == 0 { TimeLoc::current() } else { TimeLoc::of_locale(loc) };
        strftime_internal::<u32>(s, maxsize, format, &*tp, &mut tzset_called, &tl, Wc { loc, ..wc }, 0)
    }
}

pub fn format(out: &mut [u8], format: &[u8], tm: &Tm) -> Option<usize> {
    let mut fz = [0u8; 256];
    if format.len() >= fz.len() || out.is_empty() {
        return None;
    }
    fz[..format.len()].copy_from_slice(format);
    let n = unsafe { strftime(out.as_mut_ptr().cast(), out.len(), fz.as_ptr().cast(), tm) };
    if n == 0 && !format.is_empty() { None } else { Some(n) }
}


#[derive(Clone, Copy, PartialEq, Eq)]
enum Decided {
    Not,
    Loc,
    Raw,
}

#[derive(Clone, Copy)]
struct PState {
    have_i: bool,
    have_wday: bool,
    have_yday: bool,
    have_mon: bool,
    have_mday: bool,
    have_uweek: bool,
    have_wweek: bool,
    is_pm: bool,
    want_century: bool,
    want_era: bool,
    want_xday: bool,
    decided: Decided,
    week_no: i8,
    century: i8,
    era_cnt: i32,
}

const FLAT_MON_YDAY: [i32; 26] = [
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365,
    0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366,
];

fn mon_yday(leap: bool, m: isize) -> i32 {
    let f = leap as isize * 13 + m;
    if (0..26).contains(&f) {
        FLAT_MON_YDAY[f as usize]
    } else if f < 0 {
        0
    } else {
        0x7fff
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

unsafe fn match_string(name: &[u8], s: &mut *const u8) -> bool {
    unsafe {
        let ct = if rusty_libc_core::locale::ctype_special() { rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) } else { core::ptr::null() };
        for (k, &c) in name.iter().enumerate() {
            let x = *(*s).add(k);
            if x != c && rusty_libc_core::locale::tolower_in(ct, i32::from(x)) != rusty_libc_core::locale::tolower_in(ct, i32::from(c)) {
                return false;
            }
        }
        *s = (*s).add(name.len());
        true
    }
}

unsafe fn cstr_eq(mut a: *const u8, mut b: *const u8) -> bool {
    unsafe {
        while *a == *b {
            if *a == 0 {
                return true;
            }
            a = a.add(1);
            b = b.add(1);
        }
        false
    }
}

#[allow(clippy::manual_range_contains, clippy::absurd_extreme_comparisons, unused_comparisons)]
unsafe fn strptime_internal(mut rp: *const u8, mut fmt: *const u8, tmp: &mut Tm, state: Option<&mut PState>, tl: &TimeLoc) -> *const u8 {
    unsafe {
        let nested = state.is_some();
        let mut s = match &state {
            Some(st) => **st,
            None => PState {
                have_i: false,
                have_wday: false,
                have_yday: false,
                have_mon: false,
                have_mday: false,
                have_uweek: false,
                have_wweek: false,
                is_pm: false,
                want_century: false,
                want_era: false,
                want_xday: false,
                decided: Decided::Not,
                week_no: 0,
                century: -1,
                era_cnt: -1,
            },
        };
        let mut tmb = core::mem::MaybeUninit::<Tm>::uninit();
        if nested {
            tmb.write(*tmp);
        }
        let tm: &mut Tm = if nested { &mut *tmb.as_mut_ptr() } else { tmp };
        let mut val: usize;

        macro_rules! fail {
            () => {
                return core::ptr::null()
            };
        }
        macro_rules! get_number {
            ($from:expr, $to:expr, $n:expr) => {{
                let mut n: i32 = $n;
                val = 0;
                while isspace_c(*rp) {
                    rp = rp.add(1);
                }
                if *rp < b'0' || *rp > b'9' {
                    fail!();
                }
                loop {
                    val = val.wrapping_mul(10).wrapping_add((*rp - b'0') as usize);
                    rp = rp.add(1);
                    n -= 1;
                    if n <= 0 || val * 10 > $to || !(*rp).is_ascii_digit() {
                        break;
                    }
                }
                if val < $from || val > $to {
                    fail!();
                }
            }};
        }
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
                let nf: *const u8 = $f;
                if *nf == 0 {
                    false
                } else {
                    let mut s2 = s;
                    let mut tm2 = *tm;
                    let r = strptime_internal(rp, nf, &mut tm2, Some(&mut s2), tl);
                    if r.is_null() {
                        false
                    } else {
                        rp = r;
                        s = s2;
                        *tm = tm2;
                        true
                    }
                }
            }};
        }

        while *fmt != 0 {
            if isspace_c(*fmt) {
                while isspace_c(*rp) {
                    rp = rp.add(1);
                }
                fmt = fmt.add(1);
                continue;
            }
            if *fmt != b'%' {
                let (a, b) = (*fmt, *rp);
                fmt = fmt.add(1);
                rp = rp.add(1);
                if a != b {
                    fail!();
                }
                continue;
            }
            fmt = fmt.add(1);
            while matches!(*fmt, b'-' | b'_' | b'0' | b'^' | b'#') {
                fmt = fmt.add(1);
            }
            while (*fmt).is_ascii_digit() {
                fmt = fmt.add(1);
            }
            'start_over: loop {
                let rp_backup = rp;
                let _ = rp_backup;
                let conv = *fmt;
                fmt = fmt.add(1);
                match conv {
                    b'%' => {
                        let c = *rp;
                        rp = rp.add(1);
                        if c != b'%' {
                            fail!();
                        }
                    }
                    b'a' | b'A' => {
                        let c = TimeLoc::c();
                        let mut rp_longest: *const u8 = core::ptr::null();
                        let mut decided_longest = s.decided;
                        let mut cnt_longest: i32 = -1;
                        for cnt in 0..7usize {
                            let mut trp: *const u8;
                            if s.decided != Decided::Raw {
                                for (name, cname) in [(tl.day(cnt), c.day(cnt)), (tl.abday(cnt), c.abday(cnt))] {
                                    trp = rp;
                                    if match_string(name, &mut trp) && trp > rp_longest {
                                        rp_longest = trp;
                                        cnt_longest = cnt as i32;
                                        if s.decided == Decided::Not && name != cname {
                                            decided_longest = Decided::Loc;
                                        }
                                    }
                                }
                            }
                            if s.decided != Decided::Loc {
                                trp = rp;
                                let full = match_string(c.day(cnt), &mut trp) && trp > rp_longest;
                                let mut hit = full;
                                if !full {
                                    trp = rp;
                                    hit = match_string(c.abday(cnt), &mut rp) && trp > rp_longest;
                                }
                                if hit {
                                    rp_longest = trp;
                                    cnt_longest = cnt as i32;
                                    decided_longest = Decided::Raw;
                                }
                            }
                        }
                        if rp_longest.is_null() {
                            fail!();
                        }
                        rp = rp_longest;
                        s.decided = decided_longest;
                        tm.tm_wday = cnt_longest;
                        s.have_wday = true;
                    }
                    b'b' | b'B' | b'h' => {
                        let c = TimeLoc::c();
                        let mut rp_longest: *const u8 = core::ptr::null();
                        let mut decided_longest = s.decided;
                        let mut cnt_longest: i32 = -1;
                        for cnt in 0..12usize {
                            let mut trp: *const u8;
                            if s.decided != Decided::Raw {
                                for (name, cname) in [(tl.mon(cnt), c.mon(cnt)), (tl.abmon(cnt), c.abmon(cnt)), (tl.altmon(cnt), c.altmon(cnt)), (tl.abaltmon(cnt), c.altmon(cnt))] {
                                    trp = rp;
                                    if match_string(name, &mut trp) && trp > rp_longest {
                                        rp_longest = trp;
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
                                    if match_string(name, &mut trp) && trp > rp_longest {
                                        rp_longest = trp;
                                        cnt_longest = cnt as i32;
                                        decided_longest = Decided::Raw;
                                        break;
                                    }
                                }
                            }
                        }
                        if rp_longest.is_null() {
                            fail!();
                        }
                        rp = rp_longest;
                        s.decided = decided_longest;
                        tm.tm_mon = cnt_longest;
                        s.have_mon = true;
                        s.want_xday = true;
                    }
                    b'c' => {
                        if s.decided != Decided::Raw {
                            if !recursive!(tl.d_t_fmt()) {
                                if s.decided == Decided::Loc {
                                    fail!();
                                }
                                rp = rp_backup;
                            } else {
                                if s.decided == Decided::Not && !cstr_eq(tl.d_t_fmt(), timeloc::C_D_T_FMT.as_ptr()) {
                                    s.decided = Decided::Loc;
                                }
                                s.want_xday = true;
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if !recursive!(timeloc::C_D_T_FMT.as_ptr()) {
                            fail!();
                        }
                        s.want_xday = true;
                    }
                    b'C' => {
                        get_number!(0, 99, 2);
                        s.century = val as i8;
                        s.want_xday = true;
                    }
                    b'd' | b'e' => {
                        get_number!(1, 31, 2);
                        tm.tm_mday = val as c_int;
                        s.have_mday = true;
                        s.want_xday = true;
                    }
                    b'F' => {
                        if !recursive!(c"%Y-%m-%d".as_ptr().cast()) {
                            fail!();
                        }
                        s.want_xday = true;
                    }
                    b'x' | b'D' => {
                        if conv == b'x' && s.decided != Decided::Raw {
                            if !recursive!(tl.d_fmt()) {
                                if s.decided == Decided::Loc {
                                    fail!();
                                }
                                rp = rp_backup;
                            } else {
                                if s.decided == Decided::Not && !cstr_eq(tl.d_fmt(), timeloc::C_D_FMT.as_ptr()) {
                                    s.decided = Decided::Loc;
                                }
                                s.want_xday = true;
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if !recursive!(timeloc::C_D_FMT.as_ptr()) {
                            fail!();
                        }
                        s.want_xday = true;
                    }
                    b'k' | b'H' => {
                        get_number!(0, 23, 2);
                        tm.tm_hour = val as c_int;
                        s.have_i = false;
                    }
                    b'l' | b'I' => {
                        get_number!(1, 12, 2);
                        tm.tm_hour = (val % 12) as c_int;
                        s.have_i = true;
                    }
                    b'j' => {
                        get_number!(1, 366, 3);
                        tm.tm_yday = val as c_int - 1;
                        s.have_yday = true;
                    }
                    b'm' => {
                        get_number!(1, 12, 2);
                        tm.tm_mon = val as c_int - 1;
                        s.have_mon = true;
                        s.want_xday = true;
                    }
                    b'M' => {
                        get_number!(0, 59, 2);
                        tm.tm_min = val as c_int;
                    }
                    b'n' | b't' => {
                        while isspace_c(*rp) {
                            rp = rp.add(1);
                        }
                    }
                    b'p' => {
                        if s.decided != Decided::Raw {
                            if match_string(tl.ampm(false), &mut rp) {
                                if tl.ampm(false) != b"AM" {
                                    s.decided = Decided::Loc;
                                }
                                s.is_pm = false;
                                break 'start_over;
                            }
                            if match_string(tl.ampm(true), &mut rp) {
                                if tl.ampm(true) != b"PM" {
                                    s.decided = Decided::Loc;
                                }
                                s.is_pm = true;
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if match_string(b"AM", &mut rp) {
                            s.is_pm = false;
                        } else if match_string(b"PM", &mut rp) {
                            s.is_pm = true;
                        } else {
                            fail!();
                        }
                    }
                    b'r' => {
                        if s.decided != Decided::Raw {
                            if !recursive!(tl.t_fmt_ampm()) {
                                if s.decided == Decided::Loc {
                                    fail!();
                                }
                                rp = rp_backup;
                            } else {
                                if s.decided == Decided::Not && !cstr_eq(tl.t_fmt_ampm(), timeloc::C_T_FMT_AMPM.as_ptr()) {
                                    s.decided = Decided::Loc;
                                }
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if !recursive!(timeloc::C_T_FMT_AMPM.as_ptr()) {
                            fail!();
                        }
                    }
                    b'R' => {
                        if !recursive!(c"%H:%M".as_ptr().cast()) {
                            fail!();
                        }
                    }
                    b's' => {
                        let mut secs: i64 = 0;
                        if *rp < b'0' || *rp > b'9' {
                            fail!();
                        }
                        loop {
                            secs = secs.wrapping_mul(10).wrapping_add((*rp - b'0') as i64);
                            rp = rp.add(1);
                            if !(*rp >= b'0' && *rp <= b'9') {
                                break;
                            }
                        }
                        if calendar::localtime_r(&secs, tm).is_null() {
                            fail!();
                        }
                    }
                    b'S' => {
                        get_number!(0, 61, 2);
                        tm.tm_sec = val as c_int;
                    }
                    b'X' | b'T' => {
                        if conv == b'X' && s.decided != Decided::Raw {
                            if !recursive!(tl.t_fmt()) {
                                if s.decided == Decided::Loc {
                                    fail!();
                                }
                                rp = rp_backup;
                            } else {
                                if !cstr_eq(tl.t_fmt(), timeloc::C_T_FMT.as_ptr()) {
                                    s.decided = Decided::Loc;
                                }
                                break 'start_over;
                            }
                            s.decided = Decided::Raw;
                        }
                        if !recursive!(timeloc::C_T_FMT.as_ptr()) {
                            fail!();
                        }
                    }
                    b'u' => {
                        get_number!(1, 7, 1);
                        tm.tm_wday = (val % 7) as c_int;
                        s.have_wday = true;
                    }
                    b'g' => {
                        get_number!(0, 99, 2);
                    }
                    b'G' => {
                        if *rp < b'0' || *rp > b'9' {
                            fail!();
                        }
                        loop {
                            rp = rp.add(1);
                            if !(*rp >= b'0' && *rp <= b'9') {
                                break;
                            }
                        }
                    }
                    b'U' => {
                        get_number!(0, 53, 2);
                        s.week_no = val as i8;
                        s.have_uweek = true;
                    }
                    b'W' => {
                        get_number!(0, 53, 2);
                        s.week_no = val as i8;
                        s.have_wweek = true;
                    }
                    b'V' => {
                        get_number!(0, 53, 2);
                    }
                    b'w' => {
                        get_number!(0, 6, 1);
                        tm.tm_wday = val as c_int;
                        s.have_wday = true;
                    }
                    b'y' => {
                        get_number!(0, 99, 2);
                        tm.tm_year = if val >= 69 { val as c_int } else { val as c_int + 100 };
                        s.want_century = true;
                        s.want_xday = true;
                    }
                    b'Y' => {
                        get_number!(0, 9999, 4);
                        tm.tm_year = val as c_int - 1900;
                        s.want_century = false;
                        s.want_xday = true;
                    }
                    b'Z' => {
                        while isspace_c(*rp) {
                            rp = rp.add(1);
                        }
                        while !isspace_c(*rp) && *rp != 0 {
                            rp = rp.add(1);
                        }
                    }
                    b'z' => {
                        val = 0;
                        while isspace_c(*rp) {
                            rp = rp.add(1);
                        }
                        if *rp == b'Z' {
                            rp = rp.add(1);
                            tm.tm_gmtoff = 0;
                        } else {
                            if *rp != b'+' && *rp != b'-' {
                                fail!();
                            }
                            let neg = *rp == b'-';
                            rp = rp.add(1);
                            let mut n = 0;
                            while n < 4 && *rp >= b'0' && *rp <= b'9' {
                                val = val * 10 + (*rp - b'0') as usize;
                                rp = rp.add(1);
                                n += 1;
                                if *rp == b':' && n == 2 && (*rp.add(1)).is_ascii_digit() {
                                    rp = rp.add(1);
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
                        let m = *fmt;
                        fmt = fmt.add(1);
                        match m {
                            b'c' => {
                                if s.decided != Decided::Raw {
                                    let mut f2 = tl.era_d_t_fmt();
                                    if *f2 == 0 {
                                        f2 = tl.d_t_fmt();
                                    }
                                    if !recursive!(f2) {
                                        if s.decided == Decided::Loc {
                                            fail!();
                                        }
                                        rp = rp_backup;
                                    } else {
                                        if !cstr_eq(f2, timeloc::C_D_T_FMT.as_ptr()) {
                                            s.decided = Decided::Loc;
                                        }
                                        s.want_xday = true;
                                        break 'start_over;
                                    }
                                    s.decided = Decided::Raw;
                                }
                                if !recursive!(timeloc::C_D_T_FMT.as_ptr()) {
                                    fail!();
                                }
                                s.want_xday = true;
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
                                s.want_xday = true;
                            }
                            b'y' => {
                                if s.decided != Decided::Raw {
                                    get_number!(0, 9999, 4);
                                    tm.tm_year = val as c_int;
                                    s.want_era = true;
                                    s.want_xday = true;
                                    s.want_century = true;
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
                                s.want_century = true;
                                s.want_xday = true;
                            }
                            b'Y' => {
                                if s.decided != Decided::Raw {
                                    let n = tl.era_count() as i32;
                                    s.era_cnt = 0;
                                    while s.era_cnt < n {
                                        if let Some(e) = tl.era(s.era_cnt as usize)
                                            && recursive!(e.format.as_ptr())
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
                                s.want_century = false;
                                s.want_xday = true;
                            }
                            b'x' => {
                                if s.decided != Decided::Raw {
                                    let mut f2 = tl.era_d_fmt();
                                    if *f2 == 0 {
                                        f2 = tl.d_fmt();
                                    }
                                    if !recursive!(f2) {
                                        if s.decided == Decided::Loc {
                                            fail!();
                                        }
                                        rp = rp_backup;
                                    } else {
                                        if !cstr_eq(f2, timeloc::C_D_FMT.as_ptr()) {
                                            s.decided = Decided::Loc;
                                        }
                                        break 'start_over;
                                    }
                                    s.decided = Decided::Raw;
                                }
                                if !recursive!(timeloc::C_D_FMT.as_ptr()) {
                                    fail!();
                                }
                            }
                            b'X' => {
                                if s.decided != Decided::Raw {
                                    let mut f2 = tl.era_t_fmt();
                                    if *f2 == 0 {
                                        f2 = tl.t_fmt();
                                    }
                                    if !recursive!(f2) {
                                        if s.decided == Decided::Loc {
                                            fail!();
                                        }
                                        rp = rp_backup;
                                    } else {
                                        if !cstr_eq(f2, timeloc::C_T_FMT.as_ptr()) {
                                            s.decided = Decided::Loc;
                                        }
                                        break 'start_over;
                                    }
                                    s.decided = Decided::Raw;
                                }
                                if !recursive!(timeloc::C_T_FMT.as_ptr()) {
                                    fail!();
                                }
                            }
                            _ => fail!(),
                        }
                    }
                    b'O' => {
                        let m = *fmt;
                        fmt = fmt.add(1);
                        match m {
                            b'b' | b'B' | b'h' => {
                                fmt = fmt.sub(1);
                                continue 'start_over;
                            }
                            b'd' | b'e' => {
                                get_alt_number!(1, 31, 2);
                                tm.tm_mday = val as c_int;
                                s.have_mday = true;
                                s.want_xday = true;
                            }
                            b'H' => {
                                get_alt_number!(0, 23, 2);
                                tm.tm_hour = val as c_int;
                                s.have_i = false;
                            }
                            b'I' => {
                                get_alt_number!(1, 12, 2);
                                tm.tm_hour = (val % 12) as c_int;
                                s.have_i = true;
                            }
                            b'm' => {
                                get_alt_number!(1, 12, 2);
                                tm.tm_mon = val as c_int - 1;
                                s.have_mon = true;
                                s.want_xday = true;
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
                                s.have_uweek = true;
                            }
                            b'W' => {
                                get_alt_number!(0, 53, 2);
                                s.week_no = val as i8;
                                s.have_wweek = true;
                            }
                            b'V' => {
                                get_alt_number!(0, 53, 2);
                            }
                            b'w' => {
                                get_alt_number!(0, 6, 1);
                                tm.tm_wday = val as c_int;
                                s.have_wday = true;
                            }
                            b'y' => {
                                get_alt_number!(0, 99, 2);
                                tm.tm_year = if val >= 69 { val as c_int } else { val as c_int + 100 };
                                s.want_xday = true;
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
            *tmp = *tm;
            return rp;
        }

        if s.have_i && s.is_pm {
            tm.tm_hour += 12;
        }
        if s.century != -1 {
            if s.want_century {
                tm.tm_year = tm.tm_year % 100 + (s.century as c_int - 19) * 100;
            } else {
                tm.tm_year = (s.century as c_int - 19) * 100;
            }
        }
        if s.era_cnt != -1 {
            let Some(e) = tl.era(s.era_cnt as usize) else { return core::ptr::null() };
            if s.want_era {
                tm.tm_year = e.start_date[0] + (tm.tm_year - e.offset) * e.absolute_direction;
            } else {
                tm.tm_year = e.start_date[0];
            }
        } else if s.want_era && s.want_century && s.century == -1 && tm.tm_year < 69 {
            tm.tm_year += 100;
        }
        let mon_ok = |tm: &Tm, s: &PState| s.have_mon || (tm.tm_mon as u32) <= 11;
        if s.want_xday && !s.have_wday {
            if !(s.have_mon && s.have_mday) && s.have_yday {
                let leap = isleap(1900 + tm.tm_year);
                let mut t_mon = 0usize;
                while t_mon < 40 && mon_yday(leap, t_mon as isize) <= tm.tm_yday {
                    t_mon += 1;
                }
                if !s.have_mon {
                    tm.tm_mon = t_mon as c_int - 1;
                }
                if !s.have_mday {
                    tm.tm_mday = tm.tm_yday - mon_yday(leap, t_mon as isize - 1) + 1;
                }
                s.have_mon = true;
                s.have_mday = true;
            }
            if mon_ok(tm, &s) {
                day_of_the_week(tm);
            }
        }
        if s.want_xday && !s.have_yday && mon_ok(tm, &s) {
            day_of_the_year(tm);
        }
        if (s.have_uweek || s.have_wweek) && s.have_wday {
            let save_wday = tm.tm_wday;
            let save_mday = tm.tm_mday;
            let save_mon = tm.tm_mon;
            let w_offset = if s.have_uweek { 0 } else { 1 };
            tm.tm_mday = 1;
            tm.tm_mon = 0;
            day_of_the_week(tm);
            if s.have_mday {
                tm.tm_mday = save_mday;
            }
            if s.have_mon {
                tm.tm_mon = save_mon;
            }
            if !s.have_yday {
                tm.tm_yday = (7 - (tm.tm_wday - w_offset)) % 7 + (s.week_no as c_int - 1) * 7 + (save_wday - w_offset + 7) % 7;
            }
            if !s.have_mday || !s.have_mon {
                let leap = isleap(1900 + tm.tm_year);
                let mut t_mon = 0usize;
                while t_mon < 40 && mon_yday(leap, t_mon as isize) <= tm.tm_yday {
                    t_mon += 1;
                }
                if !s.have_mon {
                    tm.tm_mon = t_mon as c_int - 1;
                }
                if !s.have_mday {
                    tm.tm_mday = tm.tm_yday - mon_yday(leap, t_mon as isize - 1) + 1;
                }
            }
            tm.tm_wday = save_wday;
        }
        rp
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strptime(buf: *const c_char, format: *const c_char, tm: *mut Tm) -> *mut c_char {
    unsafe { strptime_internal(buf.cast(), format.cast(), &mut *tm, None, &TimeLoc::current()) as *mut c_char }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strptime_l(buf: *const c_char, format: *const c_char, tm: *mut Tm, loc: LocaleT) -> *mut c_char {
    unsafe { strptime_internal(buf.cast(), format.cast(), &mut *tm, None, &TimeLoc::of_locale(loc as usize)) as *mut c_char }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut getdate_err: c_int = 0;

const SYS_STAT: usize = 4;
const SYS_ACCESS: usize = 21;
const SYS_OPEN: usize = 2;
const SYS_READ: usize = 0;
const SYS_CLOSE: usize = 3;

fn first_wday(year: i32, mon: i32, wday: i32) -> i32 {
    if wday == i32::MIN {
        return 1;
    }
    let mut tm = Tm { tm_year: year, tm_mon: mon, tm_mday: 1, ..Tm::default() };
    unsafe { calendar::mktime(&mut tm) };
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdate_r(string: *const c_char, tp: *mut Tm) -> c_int {
    unsafe {
        let datemsk = env::getenv(b"DATEMSK");
        if datemsk.is_null() || *datemsk == 0 {
            return 1;
        }
        #[repr(C)]
        struct St {
            dev: u64,
            ino: u64,
            nlink: u64,
            mode: u32,
            rest: [u8; 116],
        }
        let mut st: St = core::mem::zeroed();
        if syscall::check(syscall::syscall2(SYS_STAT, datemsk as usize, &mut st as *mut St as usize)).is_err() {
            return 3;
        }
        if st.mode & 0o170000 != 0o100000 {
            return 4;
        }
        if syscall::check(syscall::syscall2(SYS_ACCESS, datemsk as usize, 4)).is_err() {
            return 2;
        }
        let fd = syscall::syscall3(SYS_OPEN, datemsk as usize, 0o2000000, 0);
        if syscall::check(fd).is_err() {
            return 2;
        }
        let mut cap = 4096usize;
        let mut data: *mut u8 = rusty_libc_malloc::malloc(cap + 1).cast();
        let mut len = 0usize;
        let mut read_error = data.is_null();
        while !read_error {
            if len == cap {
                cap *= 2;
                let n: *mut u8 = rusty_libc_malloc::realloc(data.cast(), cap + 1).cast();
                if n.is_null() {
                    read_error = true;
                    break;
                }
                data = n;
            }
            let r = syscall::syscall3(SYS_READ, fd, data.add(len) as usize, cap - len);
            match syscall::check(r) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(e) if e.0 == rusty_libc_core::errno::EINTR => {}
                Err(_) => {
                    read_error = true;
                }
            }
        }
        syscall::syscall1(SYS_CLOSE, fd);
        if data.is_null() {
            return 6;
        }
        if read_error {
            rusty_libc_malloc::free(data.cast());
            return 5;
        }
        *data.add(len) = 0;
        let mut input = string.cast::<u8>();
        while isspace_c(*input) {
            input = input.add(1);
        }
        let mut inlen = cstrlen(input);
        while inlen > 0 && isspace_c(*input.add(inlen - 1)) {
            inlen -= 1;
        }
        let instr: *mut u8 = rusty_libc_malloc::malloc(inlen + 1).cast();
        if instr.is_null() {
            rusty_libc_malloc::free(data.cast());
            return 6;
        }
        core::ptr::copy_nonoverlapping(input, instr, inlen);
        *instr.add(inlen) = 0;

        let tp = &mut *tp;
        let mut found = false;
        let mut pos = 0usize;
        while pos < len {
            let start = pos;
            while pos < len && *data.add(pos) != b'\n' {
                pos += 1;
            }
            if pos < len {
                *data.add(pos) = 0;
                pos += 1;
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
            let r = strptime_internal(instr, data.add(start), tp, None, &TimeLoc::current());
            if !r.is_null() && *r == 0 {
                found = true;
                break;
            }
        }
        rusty_libc_malloc::free(instr.cast());
        rusty_libc_malloc::free(data.cast());
        if !found {
            return 7;
        }
        let timer = crate::clock::unix_time();
        let mut tm = Tm::default();
        calendar::localtime_r(&timer, &mut tm);
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
        if (!mday_ok && !check_mday(1900i32.wrapping_add(tp.tm_year), tp.tm_mon, tp.tm_mday)) || calendar::mktime(tp) == -1 {
            return 8;
        }
        0
    }
}

static mut GETDATE_TM: Tm = Tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdate(string: *const c_char) -> *mut Tm {
    unsafe {
        let e = getdate_r(string, &raw mut GETDATE_TM);
        if e != 0 {
            getdate_err = e;
            return core::ptr::null_mut();
        }
        &raw mut GETDATE_TM
    }
}

#[allow(dead_code)]
const _: i32 = EINVAL;
#[allow(dead_code)]
fn _unused() {
    let _ = errno::get();
}

rusty_libc_core::tail_alias!(__strftime_l => strftime_l);
