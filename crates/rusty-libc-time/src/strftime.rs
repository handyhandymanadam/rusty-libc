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

fn upcase<C: Ch>(s: &mut [C], tl: &TimeLoc, wc: Wc) {
    for c in s {
        *c = c.upper(tl, wc);
    }
}

struct NulCopy<C: Unit> {
    stack: Option<[C; 128]>,
    heap: Option<MBuf<C>>,
}

impl<C: Unit> NulCopy<C> {
    fn new() -> Self {
        NulCopy { stack: None, heap: None }
    }

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

fn with_nul<C: Unit, R>(s: &[C], f: impl FnOnce(ZStr<'_, C>) -> R) -> Option<R> {
    NulCopy::new().z(s).map(f)
}

fn isleap(y: i32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn iso_week_days(yday: i32, wday: i32) -> i32 {
    let big_enough_multiple_of_7 = (366 / 7 + 2) * 7;
    yday - (yday - wday + 4 + big_enough_multiple_of_7) % 7 + 4 - 1
}

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

const TMP: usize = 32;

#[derive(Clone, Copy)]
pub enum SubF<C: Unit + 'static> {
    Z(ZStr<'static, C>),
    Tmp(usize),
    S(&'static [C]),
}

#[derive(Clone, Copy)]
enum Next<C: Unit + 'static> {
    Switch,
    Number(i32, i32, bool),
    Sub(SubF<C>),
    Bad,
}

#[derive(Clone, Copy)]
pub struct Wc {
    pub up: fn(u32, Loc) -> u32,
    pub low: fn(u32, Loc) -> u32,
    pub loc: Loc,
}

fn same(c: u32, _loc: Loc) -> u32 {
    c
}

const NARROW: Wc = Wc { up: same, low: same, loc: Loc::CURRENT };

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

pub trait Ch: Copy + 'static + Unit {
    const WIDE: bool;
    fn asc(self) -> u8;
    fn from_u8(b: u8) -> Self;
    fn lower(self, tl: &TimeLoc, wc: Wc) -> Self;
    fn upper(self, tl: &TimeLoc, wc: Wc) -> Self;
    fn text(tl: &TimeLoc, it: It, tmp: &mut [Self; TMP]) -> Text<Self>;
    fn subfmt(tl: &TimeLoc, it: It, tmp: &mut [Self; TMP]) -> SubF<Self>;
    fn copy(dst: &mut [Self], src: &[Self]);
    fn copy_ascii(dst: &mut [Self], src: &[u8]);
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
    fn subfmt(tl: &TimeLoc, it: It, tmp: &mut [u32; TMP]) -> SubF<u32> {
        match Self::text(tl, it, tmp) {
            Text::Static(s) => SubF::S(s),
            Text::Tmp(n) => SubF::Tmp(n),
        }
    }
    fn text(tl: &TimeLoc, it: It, tmp: &mut [u32; TMP]) -> Text<u32> {
        use rusty_libc_core::locale::idx;
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
}

#[inline(never)]
fn fill<C: Ch>(dst: &mut [C], b: u8) {
    for d in dst {
        *d = C::from_u8(b);
    }
}

#[inline(always)]
fn pad_units<C: Ch>(dst: &mut [C], b: u8) {
    if let [d] = dst {
        *d = C::from_u8(b);
    } else {
        fill(dst, b);
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
fn rv<T: Copy>(r: &T) -> T {
    unsafe { core::ptr::read_volatile(r) }
}

#[allow(clippy::too_many_arguments)]
fn strftime_internal<C: Ch>(s: Option<&mut [C]>, maxsize: usize, mut fz: ZStr<'_, C>, tp: &Tm, tzset_called: &mut bool, tl: &TimeLoc, wc: Wc, yr_spec: u8) -> usize {
    let mut yr_spec = yr_spec;
    let mut zone: *const c_char = rv(&tp.tm_zone);
    macro_rules! hour12 {
        () => {{
            let h = rv(&tp.tm_hour);
            if h > 12 { h - 12 } else if h == 0 { 12 } else { h }
        }};
    }
    let mut i = 0usize;
    let mut out = s;
    let mut buf = [0u8; 24];
    let mut tmp = [C::from_u8(0); TMP];

    while !fz.at_end() {
        let mut pad: u8 = 0;
        let mut width: i32 = -1;
        let mut to_lowcase = false;
        let mut to_uppcase = false;
        let mut change_case = false;

        macro_rules! room {
            () => {
                match &out {
                    Some(o) => o.len(),
                    None => maxsize.wrapping_sub(i),
                }
            };
        }
        macro_rules! add {
            ($n:expr, |$q:ident| $body:expr) => {{
                let n: i32 = $n as i32;
                let delta = width - n;
                let incr = n + if delta > 0 { delta } else { 0 };
                match out.take() {
                    Some(o) => {
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
                if 1 >= room!() {
                    return 0;
                }
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
            let start = fz.pos();
            while !t.at_end() && t.cur().asc() != b'%' {
                t.bump();
            }
            if t.pos() - start >= room!() {
                if 1 >= room!() {
                    return 0;
                }
                t = fz;
                t.bump();
            }
            let run = &t.scanned()[start..];
            if let Some(o) = out.take() {
                let (head, rest) = o.split_at_mut(run.len());
                C::copy(head, run);
                out = Some(rest);
            }
            i += run.len();
            fz = t;
            continue;
        }
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
        let modifier = if fz.cur().asc() == b'E' || fz.cur().asc() == b'O' {
            let m = fz.cur().asc();
            fz.bump();
            m
        } else {
            0
        };
        let format_char = fz.cur().asc();
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
                            let t = if (0..=6).contains(&rv(&tp.tm_wday)) { text!(It::AbDay(rv(&tp.tm_wday) as usize)) } else { text!(It::Lit(b"?\0")) };
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
                            let t = if (0..=6).contains(&rv(&tp.tm_wday)) { text!(It::Day(rv(&tp.tm_wday) as usize)) } else { text!(It::Lit(b"?\0")) };
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
                            let t = if !(0..=11).contains(&rv(&tp.tm_mon)) {
                                text!(It::Lit(b"?\0"))
                            } else if modifier == b'O' {
                                text!(It::AbAltMon(rv(&tp.tm_mon) as usize))
                            } else {
                                text!(It::AbMon(rv(&tp.tm_mon) as usize))
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
                            let t = if !(0..=11).contains(&rv(&tp.tm_mon)) {
                                text!(It::Lit(b"?\0"))
                            } else if modifier == b'O' {
                                text!(It::AltMon(rv(&tp.tm_mon) as usize))
                            } else {
                                text!(It::Mon(rv(&tp.tm_mon) as usize))
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
                                let delta = rv(&tp.tm_year) - era.start_date[0];
                                if yr_spec != 0 {
                                    pad = yr_spec;
                                }
                                number!(2, era.offset + delta * era.absolute_direction);
                            }
                            number!(2, tm_number(b'y', tp));
                        }
                        b'Z' => {
                            if change_case && !C::WIDE {
                                to_uppcase = false;
                                to_lowcase = true;
                            }
                            if C::WIDE && pad == b'-' {
                                width = -1;
                            }
                            let mut zb: Option<&[u8]> = unsafe { ffi::cstr(zone) }.map(|z| z.to_bytes());
                            if zb.is_none_or(|z| z.is_empty()) && rv(&tp.tm_isdst) >= 0 {
                                if !*tzset_called {
                                    tz::tzset_now();
                                    *tzset_called = true;
                                }
                                zone = if rv(&tp.tm_isdst) <= 1 { tz::tzname_ptr(rv(&tp.tm_isdst) as usize) } else { c"?".as_ptr() };
                                zb = unsafe { ffi::cstr(zone) }.map(|z| z.to_bytes());
                            }
                            cpyb!(zb.unwrap_or(b""));
                        }
                        b'z' => {
                            if rv(&tp.tm_isdst) < 0 {
                            } else {
                                let mut diff = rv(&tp.tm_gmtoff) as i32;
                                if diff < 0 {
                                    add!(1, |q| q[0] = C::from_u8(b'-'));
                                    diff = diff.wrapping_neg();
                                } else {
                                    add!(1, |q| q[0] = C::from_u8(b'+'));
                                }
                                diff /= 60;
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
                    let digits = if digits > width { digits } else { width };
                    if spacepad && pad != b'0' && pad != b'-' {
                        pad = b'_';
                    }
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

#[inline(never)]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn sub_format<'o, C: Ch>(subt: SubF<C>, tmp: &[C; TMP], mut out: Option<&'o mut [C]>, i: usize, maxsize: usize, width: i32, pad: u8, to_uppcase: bool, tp: &Tm, tzset_called: &mut bool, tl: &TimeLoc, wc: Wc, yr_spec: u8) -> Option<(Option<&'o mut [C]>, usize)> {
    let mut copy = NulCopy::new();
    let subfmt: ZStr<'_, C> = match subt {
        SubF::Z(z) => z,
        SubF::Tmp(n) => match ZStr::from_nul_terminated(&tmp[..=n]) {
            Some(z) => z,
            None => return Some((out, i)),
        },
        SubF::S(sl) => copy.z(sl)?,
    };
    if width <= 0
        && tl.is_c()
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
        len
    };
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
                C::copy(&mut q[..n], &scratch[..n]);
                q[n] = C::from_u8(0);
            } else {
                let room = q.len();
                let _ = strftime_internal(Some(&mut q[..]), room, subfmt, tp, tzset_called, tl, wc, yr_spec);
            }
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

unsafe fn out_buf<'a, C>(s: *mut C, maxsize: usize) -> (Option<&'a mut [C]>, usize) {
    if s.is_null() {
        return (None, maxsize);
    }
    let cap = maxsize.min(isize::MAX as usize / size_of::<C>());
    (Some(unsafe { ffi::slice_mut(s, cap) }), cap)
}

unsafe fn strftime_c(s: *mut c_char, maxsize: usize, format: *const c_char, tp: *const Tm, tl: &TimeLoc) -> usize {
    let format = unsafe { ZStr::new(format.cast::<u8>()) };
    let tm = unsafe { sys::arg(tp) };
    let (out, cap) = unsafe { out_buf(s.cast::<u8>(), maxsize) };
    let mut tzset_called = false;
    strftime_internal::<u8>(out, cap, format, tm, &mut tzset_called, tl, NARROW, 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strftime(s: *mut c_char, maxsize: usize, format: *const c_char, tp: *const Tm) -> usize {
    unsafe { strftime_c(s, maxsize, format, tp, &TimeLoc::current()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strftime_l(s: *mut c_char, maxsize: usize, format: *const c_char, tp: *const Tm, loc: LocaleT) -> usize {
    let tl = unsafe { TimeLoc::of_locale(loc as usize) };
    unsafe { strftime_c(s, maxsize, format, tp, &tl) }
}

pub unsafe fn wcsftime_with(s: *mut u32, maxsize: usize, format: *const u32, tp: *const Tm, loc: usize, wc: Wc) -> usize {
    let format = unsafe { ZStr::new(format) };
    let tm = unsafe { sys::arg(tp) };
    let (out, cap) = unsafe { out_buf(s, maxsize) };
    let mut tzset_called = false;
    let tl = if loc == 0 { TimeLoc::current() } else { unsafe { TimeLoc::of_locale(loc) } };
    let loc = unsafe { Loc::from_raw(loc) };
    strftime_internal::<u32>(out, cap, format, tm, &mut tzset_called, &tl, Wc { loc, ..wc }, 0)
}

pub fn format(out: &mut [u8], format: &[u8], tm: &Tm) -> Option<usize> {
    if format.len() >= 256 || out.is_empty() {
        return None;
    }
    let fmt = &format[..format.iter().position(|&c| c == 0).unwrap_or(format.len())];
    let mut tzset_called = false;
    let cap = out.len();
    let n = with_nul(fmt, |z| strftime_internal::<u8>(Some(out), cap, z, tm, &mut tzset_called, &TimeLoc::current(), NARROW, 0))?;
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

#[inline(always)]
fn match_string(name: &[u8], rp: &mut ZStr<'_, u8>) -> bool {
    let ct = if rusty_libc_core::locale::ctype_special() { rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) } else { None };
    let mut t = *rp;
    for &c in name {
        let x = t.cur();
        if x != c && rusty_libc_core::locale::tolower_in(ct, i32::from(x)) != rusty_libc_core::locale::tolower_in(ct, i32::from(c)) {
            return false;
        }
        t.bump();
    }
    *rp = t;
    true
}

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

unsafe fn strptime_c(buf: *const c_char, format: *const c_char, tm: *mut Tm, tl: &TimeLoc) -> *mut c_char {
    let input = unsafe { ZStr::new(buf.cast::<u8>()) };
    let fmt = unsafe { ZStr::new(format.cast::<u8>()) };
    let tm = unsafe { sys::arg_mut(tm) };
    match strptime_internal(input, fmt, tm, None, tl) {
        Some(end) => buf.wrapping_add(end.pos()).cast_mut(),
        None => core::ptr::null_mut(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strptime(buf: *const c_char, format: *const c_char, tm: *mut Tm) -> *mut c_char {
    unsafe { strptime_c(buf, format, tm, &TimeLoc::current()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strptime_l(buf: *const c_char, format: *const c_char, tm: *mut Tm, loc: LocaleT) -> *mut c_char {
    let tl = unsafe { TimeLoc::of_locale(loc as usize) };
    unsafe { strptime_c(buf, format, tm, &tl) }
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdate_r(string: *const c_char, tp: *mut Tm) -> c_int {
    let input = || unsafe { ffi::cstr_bytes(string) };
    let tp = unsafe { sys::arg_mut(tp) };
    getdate_tm(input, tp)
}

static GETDATE_TM: SyncCell<Tm> = SyncCell::new(Tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() });

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdate(string: *const c_char) -> *mut Tm {
    let input = || unsafe { ffi::cstr_bytes(string) };
    let e = unsafe { GETDATE_TM.with_unsync(|tm| getdate_tm(input, tm)) };
    if e != 0 {
        getdate_err.store(e, Relaxed);
        return core::ptr::null_mut();
    }
    GETDATE_TM.as_ptr()
}

rusty_libc_core::tail_alias!(__strftime_l => strftime_l);
