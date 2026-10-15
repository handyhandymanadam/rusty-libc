use crate::{Charset, charset, mbstate_t, wchar_t, wint_t, WEOF};
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::ffi::{bytes, out, slice_mut};
use rusty_libc_core::sync_cell::SyncCell;

pub const EILSEQ: i32 = 84;
pub const MB_LEN_MAX: usize = 16;

const ERR: usize = usize::MAX;
const INCOMPLETE: usize = usize::MAX - 1;
const PENDING: usize = usize::MAX - 2;

const MAX_ELEMS: usize = isize::MAX as usize / 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Empty,
    Full,
    Illegal,
    Incomplete,
}

type Hidden = SyncCell<mbstate_t>;
const INITIAL: mbstate_t = mbstate_t { count: 0, value: 0 };

static S_MBRTOWC: Hidden = Hidden::new(INITIAL);
static S_MBRLEN: Hidden = Hidden::new(INITIAL);
static S_MBSRTOWCS: Hidden = Hidden::new(INITIAL);
static S_MBSNRTOWCS: Hidden = Hidden::new(INITIAL);
static S_WCRTOMB: Hidden = Hidden::new(INITIAL);
static S_WCSRTOMBS: Hidden = Hidden::new(INITIAL);
static S_WCSNRTOMBS: Hidden = Hidden::new(INITIAL);
static S_MBTOWC: Hidden = Hidden::new(INITIAL);
static S_WCTOMB: Hidden = Hidden::new(INITIAL);
static S_MBRTOC8: Hidden = Hidden::new(INITIAL);
static S_C8RTOMB: Hidden = Hidden::new(INITIAL);
static S_MBRTOC16: Hidden = Hidden::new(INITIAL);
static S_C16RTOMB: Hidden = Hidden::new(INITIAL);
static S_MBRTOC32: Hidden = Hidden::new(INITIAL);
static S_C32RTOMB: Hidden = Hidden::new(INITIAL);

#[inline(always)]
unsafe fn state<'a>(ps: *mut mbstate_t, own: &'static Hidden) -> &'a mut mbstate_t {
    let p = if ps.is_null() { own.as_ptr() } else { ps };
    unsafe { &mut *p }
}

enum Dec {
    Ok(u32, usize),
    Incomplete,
    Illegal,
}

#[inline(always)]
fn lead(b0: u8) -> Option<(usize, u8)> {
    match b0 {
        0xc2..=0xdf => Some((2, 0x1f)),
        0xe0..=0xef => Some((3, 0x0f)),
        0xf0..=0xf7 => Some((4, 0x07)),
        0xf8..=0xfb => Some((5, 0x03)),
        0xfc..=0xfd => Some((6, 0x01)),
        _ => None,
    }
}

#[inline(always)]
fn decode(b: &[u8]) -> Dec {
    let b0 = b[0];
    if b0 < 0x80 {
        return Dec::Ok(u32::from(b0), 1);
    }
    let Some((cnt, mask)) = lead(b0) else { return Dec::Illegal };
    if b.len() < cnt {
        if b[1..].iter().any(|&c| c & 0xc0 != 0x80) {
            return Dec::Illegal;
        }
        return Dec::Incomplete;
    }
    let mut ch = u32::from(b0 & mask);
    for &c in &b[1..cnt] {
        if c & 0xc0 != 0x80 {
            return Dec::Illegal;
        }
        ch = (ch << 6) | u32::from(c & 0x3f);
    }
    if (cnt > 2 && (ch >> (5 * cnt - 4)) == 0) || (0xd800..=0xdfff).contains(&ch) {
        return Dec::Illegal;
    }
    Dec::Ok(ch, cnt)
}

fn store_rest(st: &mut mbstate_t, b: &[u8]) {
    let m = b.len();
    let (cnt, mask) = lead(b[0]).unwrap_or((6, 0x01));
    let mut ch = u32::from(b[0] & mask);
    for &c in &b[1..] {
        ch = (ch << 6) | u32::from(c & 0x3f);
    }
    let r = cnt - m;
    ch = ch.wrapping_shl((r * 6) as u32);
    st.count = m as i32 | ((cnt as i32) << 8);
    st.value = ch;
}

fn utf8_towc(st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    let mut pos = 0usize;
    let mut produced = 0usize;
    if st.count & 7 != 0 {
        let inlen = (st.count & 255) as usize;
        let ntotal = (st.count as u32 >> 8) as usize;
        if !(2..=6).contains(&ntotal) || inlen == 0 || inlen >= ntotal {
            return (Status::Illegal, 0, 0);
        }
        if out.is_empty() {
            return (Status::Full, 0, 0);
        }
        if src.is_empty() {
            return (Status::Empty, 0, 0);
        }
        const INMASK: [u8; 5] = [0xc0, 0xe0, 0xf0, 0xf8, 0xfc];
        let mut buf = [0u8; 6];
        buf[0] = INMASK[ntotal - 2];
        let mut wch = st.value;
        let mut nt = ntotal;
        loop {
            nt -= 1;
            if nt < inlen {
                buf[nt] = 0x80 | (wch & 0x3f) as u8;
            }
            wch >>= 6;
            if nt <= 1 {
                break;
            }
        }
        buf[0] |= wch as u8;
        let taken = (6 - inlen).min(src.len());
        let total = inlen + taken;
        buf[inlen..total].copy_from_slice(&src[..taken]);
        match decode(&buf[..total]) {
            Dec::Ok(ch, cnt) => {
                pos = cnt.saturating_sub(inlen);
                out[0] = ch;
                produced = 1;
                st.count = 0;
            }
            Dec::Incomplete => {
                store_rest(st, &buf[..total]);
                return (Status::Incomplete, taken, 0);
            }
            Dec::Illegal => return (Status::Illegal, 0, 0),
        }
    }
    loop {
        let (s, o) = (&src[pos..], &mut out[produced..]);
        let m = s.len().min(o.len());
        let mut k = 0;
        while k < m && s[k] < 0x80 {
            o[k] = u32::from(s[k]);
            k += 1;
        }
        pos += k;
        produced += k;
        if pos == src.len() {
            return (Status::Empty, pos, produced);
        }
        if produced == out.len() {
            return (Status::Full, pos, produced);
        }
        match decode(&src[pos..]) {
            Dec::Ok(ch, cnt) => {
                out[produced] = ch;
                produced += 1;
                pos += cnt;
            }
            Dec::Incomplete => {
                store_rest(st, &src[pos..]);
                return (Status::Incomplete, src.len(), produced);
            }
            Dec::Illegal => return (Status::Illegal, pos, produced),
        }
    }
}

fn ascii_towc(src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    let n = src.len().min(out.len());
    for (i, (&b, o)) in src.iter().zip(out.iter_mut()).enumerate() {
        if b > 0x7f {
            return (Status::Illegal, i, i);
        }
        *o = u32::from(b);
    }
    (if n == src.len() { Status::Empty } else { Status::Full }, n, n)
}

#[inline(always)]
fn towc_cs(cs: Charset, st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    match cs {
        Charset::Utf8 => utf8_towc(st, src, out),
        Charset::C => ascii_towc(src, out),
        Charset::Other => other_towc(st, src, out),
    }
}

#[inline(always)]
fn towc(st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    towc_cs(charset(), st, src, out)
}

pub fn codeset_name() -> ([u8; 48], usize) {
    let mut b = [0u8; 48];
    let Some(d) = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) else {
        return (b, 0);
    };
    let s = d.bytes(14);
    let n = s.len().min(47);
    b[..n].copy_from_slice(&s[..n]);
    (b, n)
}

pub type OtherToWc = unsafe fn(&mut mbstate_t, &mut *const u8, usize, *mut u32, usize) -> (Status, usize);
pub type OtherEncode = fn(u32, &mut [u8; 6]) -> Option<usize>;
pub type OtherToMb = unsafe fn(&mut mbstate_t, &mut *const u32, usize, *mut u8, usize) -> (Status, usize);
pub type OtherEach = fn(&mut dyn FnMut(&[u8], u32));

static OTHER_TOWC: AtomicUsize = AtomicUsize::new(0);
static OTHER_ENCODE: AtomicUsize = AtomicUsize::new(0);
static OTHER_EACH: AtomicUsize = AtomicUsize::new(0);
static OTHER_TOMB: AtomicUsize = AtomicUsize::new(0);

pub fn set_other_hooks(towc: OtherToWc, encode: OtherEncode, each: OtherEach, tomb: OtherToMb) {
    OTHER_TOMB.store(tomb as usize, Ordering::Release);
    OTHER_TOWC.store(towc as usize, Ordering::Release);
    OTHER_ENCODE.store(encode as usize, Ordering::Release);
    OTHER_EACH.store(each as usize, Ordering::Release);
}

pub fn each_other_char(f: &mut dyn FnMut(&[u8], u32)) {
    let h = OTHER_EACH.load(Ordering::Acquire);
    if h != 0 {
        let h: OtherEach = unsafe { core::mem::transmute::<usize, OtherEach>(h) };
        h(f);
    }
}

#[inline(always)]
fn towc_hook() -> Option<OtherToWc> {
    let f = OTHER_TOWC.load(Ordering::Acquire);
    (f != 0).then(|| unsafe { core::mem::transmute::<usize, OtherToWc>(f) })
}

unsafe fn other_towc_raw(st: &mut mbstate_t, src: *const u8, avail: usize, out: &mut [u32]) -> (Status, usize, usize) {
    let Some(f) = towc_hook() else { return (Status::Illegal, 0, 0) };
    let mut p = src;
    let (s, n) = unsafe { f(st, &mut p, avail, out.as_mut_ptr(), out.len()) };
    (s, p as usize - src as usize, n)
}

fn other_towc(st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    unsafe { other_towc_raw(st, src.as_ptr(), src.len(), out) }
}

fn other_tomb(st: &mut mbstate_t, src: &[u8], out: &mut [u8]) -> (Status, usize, usize) {
    let f = OTHER_TOMB.load(Ordering::Acquire);
    if f == 0 {
        return (Status::Illegal, 0, 0);
    }
    let f: OtherToMb = unsafe { core::mem::transmute::<usize, OtherToMb>(f) };
    let start = src.as_ptr().cast::<u32>();
    let mut p = start;
    let (s, n) = unsafe { f(st, &mut p, src.len() / 4, out.as_mut_ptr(), out.len()) };
    (s, (p as usize - start as usize) / 4, n)
}

fn other_encode(wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    let f = OTHER_ENCODE.load(Ordering::Acquire);
    if f == 0 {
        return None;
    }
    let f: OtherEncode = unsafe { core::mem::transmute::<usize, OtherEncode>(f) };
    f(wc, out)
}

fn encode_utf8(wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    if wc < 0x80 {
        out[0] = wc as u8;
        return Some(1);
    }
    if wc > 0x7fff_ffff || (0xd800..=0xdfff).contains(&wc) {
        return None;
    }
    let mut step = 2usize;
    while step < 6 && (wc & (!0u32 << (5 * step + 1))) != 0 {
        step += 1;
    }
    out[0] = (0xffff_ff00u32 >> step) as u8;
    let mut w = wc;
    let mut i = step;
    while i > 1 {
        i -= 1;
        out[i] = 0x80 | (w & 0x3f) as u8;
        w >>= 6;
    }
    out[0] |= w as u8;
    Some(step)
}

#[inline(always)]
fn unit(src: &[u8], k: usize) -> u32 {
    let b: [u8; 4] = src[4 * k..4 * k + 4].try_into().unwrap_or([0; 4]);
    u32::from_ne_bytes(b)
}

fn tomb(st: &mut mbstate_t, src: &[u8], out: &mut [u8]) -> (Status, usize, usize) {
    tomb_cs(charset(), st, src, out)
}

fn tomb_cs(cs: Charset, st: &mut mbstate_t, src: &[u8], out: &mut [u8]) -> (Status, usize, usize) {
    let units = src.len() / 4;
    if cs == Charset::Other {
        if units != 0 && out.is_empty() {
            return (Status::Full, 0, 0);
        }
        return other_tomb(st, &src[..units * 4], out);
    }
    let cap = out.len();
    let (mut i, mut produced) = (0usize, 0usize);
    loop {
        let mut run = 0;
        for (sb, ob) in src[4 * i..4 * units].as_chunks::<16>().0.iter().zip(out[produced..].as_chunks_mut::<4>().0) {
            let [a, b, c, d] = [0, 1, 2, 3].map(|k| u32::from_ne_bytes([sb[4 * k], sb[4 * k + 1], sb[4 * k + 2], sb[4 * k + 3]]));
            if (a | b | c | d) >= 0x80 {
                break;
            }
            *ob = (a | (b << 8) | (c << 16) | (d << 24)).to_le_bytes();
            run += 4;
        }
        i += run;
        produced += run;
        while i < units && produced < cap {
            let wc = unit(src, i);
            if wc >= 0x80 {
                break;
            }
            out[produced] = wc as u8;
            produced += 1;
            i += 1;
        }
        if i == units {
            return (Status::Empty, i, produced);
        }
        if produced >= cap {
            return (Status::Full, i, produced);
        }
        let wc = unit(src, i);
        let mut b = [0u8; 6];
        let n = match cs {
            Charset::Utf8 => encode_utf8(wc, &mut b),
            Charset::C => {
                b[0] = wc as u8;
                if wc <= 0x7f { Some(1) } else { None }
            }
            Charset::Other => other_encode(wc, &mut b),
        };
        let Some(n) = n else {
            if (wc >> 7) == (0xe0000 >> 7) {
                i += 1;
                continue;
            }
            return (Status::Illegal, i, produced);
        };
        let Some(dst) = out.get_mut(produced..produced + n) else { return (Status::Full, i, produced) };
        for (d, &x) in dst.iter_mut().zip(&b[..n]) {
            *d = x;
        }
        produced += n;
        i += 1;
    }
}

fn tomb_stateful(ps: &mut mbstate_t, src: &[u8], out: &mut [u8]) -> (Status, usize, usize) {
    let avail = src.len();
    let mut pos = 0usize;
    let mut produced = 0usize;
    let n = (ps.count & 7) as usize;
    if n != 0 {
        let need = 4 - n;
        if out.is_empty() {
            return (Status::Full, 0, 0);
        }
        let mut bytes = ps.value.to_le_bytes();
        if avail < need {
            bytes[n..n + avail].copy_from_slice(src);
            ps.value = u32::from_le_bytes(bytes);
            ps.count = (ps.count & !7) | (n + avail) as i32;
            return (Status::Incomplete, avail, 0);
        }
        bytes[n..].copy_from_slice(&src[..need]);
        let wc = u32::from_le_bytes(bytes);
        let mut b = [0u8; 6];
        let Some(len) = encode_utf8(wc, &mut b) else { return (Status::Illegal, 0, 0) };
        if len > out.len() {
            return (Status::Full, 0, 0);
        }
        out[..len].copy_from_slice(&b[..len]);
        produced = len;
        ps.count &= !7;
        pos = need;
    }
    let rest = &src[pos..];
    let whole = rest.len() / 4 * 4;
    let (status, used, p) = tomb(ps, &rest[..whole], &mut out[produced..]);
    produced += p;
    pos += used * 4;
    if status == Status::Empty && pos != avail {
        let tail = &src[pos..];
        let mut bytes = ps.value.to_le_bytes();
        bytes[..tail.len()].copy_from_slice(tail);
        ps.value = u32::from_le_bytes(bytes);
        ps.count = (ps.count & !7) | tail.len() as i32;
        return (Status::Incomplete, avail, produced);
    }
    (status, pos, produced)
}

#[inline(always)]
unsafe fn mbrtowc_in(pwc: *mut wchar_t, s: *const c_char, n: usize, st: &mut mbstate_t) -> usize {
    let (pwc, s, n) = if s.is_null() { (core::ptr::null_mut(), c"".as_ptr(), 1) } else { (pwc, s, n) };
    if n == 0 {
        return INCOMPLETE;
    }
    let cs = charset();
    if cs != Charset::Other && st.count & 7 == 0 {
        let src = unsafe { bytes(s.cast::<u8>(), n.min(MB_LEN_MAX)) };
        let d = if cs == Charset::Utf8 {
            decode(src)
        } else if src[0] < 0x80 {
            Dec::Ok(u32::from(src[0]), 1)
        } else {
            Dec::Illegal
        };
        return match d {
            Dec::Ok(ch, cnt) => {
                if let Some(w) = unsafe { out(pwc) } {
                    *w = ch as wchar_t;
                }
                if ch == 0 { 0 } else { cnt }
            }
            Dec::Incomplete => {
                store_rest(st, src);
                INCOMPLETE
            }
            Dec::Illegal => {
                errno::set(EILSEQ);
                ERR
            }
        };
    }
    unsafe { mbrtowc_slow(pwc, s, n, st, cs) }
}

#[inline(never)]
unsafe fn mbrtowc_slow(pwc: *mut wchar_t, s: *const c_char, n: usize, st: &mut mbstate_t, cs: Charset) -> usize {
    let mut buf = 0u32;
    let out: &mut [u32] = match pwc.is_null() {
        true => core::slice::from_mut(&mut buf),
        false => unsafe { slice_mut(pwc.cast::<u32>(), 1) },
    };
    let (status, used, produced) = if cs == Charset::Other {
        unsafe { other_towc_raw(st, s.cast(), n, out) }
    } else {
        towc_cs(cs, st, unsafe { bytes(s.cast(), n.min(MB_LEN_MAX)) }, out)
    };
    match status {
        Status::Empty | Status::Full => {
            if produced > 0 && out[0] == 0 {
                0
            } else {
                used
            }
        }
        Status::Incomplete => INCOMPLETE,
        Status::Illegal => {
            errno::set(EILSEQ);
            ERR
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtowc(pwc: *mut wchar_t, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_MBRTOWC) };
    unsafe { mbrtowc_in(pwc, s, n, st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbrlen(s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    unsafe { mbrlen(s, n, ps) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrlen(s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_MBRLEN) };
    unsafe { mbrtowc_in(core::ptr::null_mut(), s, n, st) }
}

fn wcrtomb_buf(cs: Charset, wc: u32, st: &mut mbstate_t, buf: &mut [u8; MB_LEN_MAX]) -> Option<usize> {
    if wc == 0 {
        let produced = if cs == Charset::Other && (st.count & !7) != 0 {
            tomb_cs(cs, st, &wc.to_ne_bytes(), buf).2
        } else {
            buf[0] = 0;
            1
        };
        *st = mbstate_t::default();
        return Some(produced);
    }
    if cs == Charset::Utf8 && st.count & 7 != 0 {
        let k = (st.count & 7) as usize;
        if k <= 3 {
            let mut four = [0u8; 4];
            four[..k].copy_from_slice(&st.value.to_le_bytes()[..k]);
            four[k..].copy_from_slice(&wc.to_le_bytes()[..4 - k]);
            let mut e = [0u8; 6];
            if encode_utf8(u32::from_le_bytes(four), &mut e).is_some() {
                let mut v = st.value.to_le_bytes();
                v[..k].copy_from_slice(&wc.to_le_bytes()[4 - k..]);
                st.value = u32::from_le_bytes(v);
                st.count = (st.count & !7) | k as i32;
            }
        }
        errno::set(EILSEQ);
        return None;
    }
    let (status, _, produced) = tomb_cs(cs, st, &wc.to_ne_bytes(), buf);
    if status == Status::Illegal || status == Status::Incomplete {
        errno::set(EILSEQ);
        return None;
    }
    Some(produced)
}

#[inline(always)]
unsafe fn wcrtomb_in(s: *mut c_char, wc: wchar_t, st: &mut mbstate_t) -> usize {
    let wc = if s.is_null() { 0 } else { wc as u32 };
    let cs = charset();
    if (1..0x80).contains(&wc) && st.count & 7 == 0 && cs != Charset::Other {
        unsafe { *s = wc as c_char };
        return 1;
    }
    if cs == Charset::Utf8 && st.count & 7 == 0 && wc != 0 {
        let mut e = [0u8; 6];
        let Some(n) = encode_utf8(wc, &mut e) else {
            errno::set(EILSEQ);
            return ERR;
        };
        for (d, &b) in unsafe { slice_mut(s.cast::<u8>(), n) }.iter_mut().zip(&e[..n]) {
            *d = b;
        }
        return n;
    }
    let mut buf = [0u8; MB_LEN_MAX];
    let Some(n) = wcrtomb_buf(cs, wc, st, &mut buf) else { return ERR };
    if !s.is_null() {
        unsafe { slice_mut(s.cast::<u8>(), n) }.copy_from_slice(&buf[..n]);
    }
    n
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcrtomb(s: *mut c_char, wc: wchar_t, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_WCRTOMB) };
    unsafe { wcrtomb_in(s, wc, st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsinit(ps: *const mbstate_t) -> c_int {
    c_int::from(unsafe { ps.as_ref() }.is_none_or(|p| p.count == 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn btowc(c: c_int) -> wint_t {
    if (0..=0x7f).contains(&c) {
        return c as wint_t;
    }
    let c = if (-128..-1).contains(&c) { c & 0xff } else { c };
    if charset() == Charset::Other && (0x80..=0xff).contains(&c) {
        let (name, nl) = codeset_name();
        if c == 0x80 && name[..nl].eq_ignore_ascii_case(b"GBK") {
            return WEOF;
        }
        let mut st = mbstate_t::default();
        let mut w = 0u32;
        let (status, _, produced) = other_towc(&mut st, &[c as u8], core::slice::from_mut(&mut w));
        if produced == 1 && status != Status::Illegal {
            BTOWC_SLOT.store(w, Ordering::Relaxed);
            return w;
        }
        if produced == 0 && status == Status::Empty {
            return BTOWC_SLOT.load(Ordering::Relaxed);
        }
    }
    WEOF
}

static BTOWC_SLOT: AtomicU32 = AtomicU32::new(0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctob(c: wint_t) -> c_int {
    if c <= 0x7f {
        return c as c_int;
    }
    if charset() == Charset::Other {
        let mut b = [0u8; 6];
        if let Some(1) = other_encode(c, &mut b) {
            return i32::from(b[0]);
        }
    }
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_get_mb_cur_max() -> usize {
    mb_cur_max()
}

#[inline]
pub fn mb_cur_max() -> usize {
    match charset() {
        Charset::C => 1,
        Charset::Utf8 => 6,
        Charset::Other => {
            rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE).map_or(1, |d| (d.word(13) as usize).max(1))
        }
    }
}

#[inline(always)]
unsafe fn cstr_with_nul<'a>(p: *const c_char) -> &'a [u8] {
    let n = unsafe { rusty_libc_core::ffi::cstr_len(p) } + 1;
    unsafe { bytes(p.cast(), n) }
}

#[inline(always)]
unsafe fn cstr_upto<'a>(p: *const c_char, n: usize) -> &'a [u8] {
    let l = unsafe { rusty_libc_mem::strnlen(p, n) };
    unsafe { bytes(p.cast(), l + 1) }
}

#[inline(always)]
fn wide_bytes(s: &[u32]) -> &[u8] {
    unsafe { core::slice::from_raw_parts(s.as_ptr().cast::<u8>(), s.len() * 4) }
}

fn count_towc(st: &mbstate_t, src: &[u8]) -> (Status, usize, u32) {
    let mut temp = *st;
    let mut buf = [0u32; 64];
    let (mut pos, mut result, mut last) = (0usize, 0usize, 1u32);
    loop {
        let (s, used, produced) = towc(&mut temp, &src[pos..], &mut buf);
        pos += used;
        result += produced;
        if produced > 0 {
            last = buf[produced - 1];
        }
        if s != Status::Full {
            return (s, result, last);
        }
    }
}

unsafe fn mbsrtowcs_in(dst: *mut wchar_t, src: *mut *const c_char, len: usize, ps: &mut mbstate_t) -> usize {
    let start = unsafe { *src };
    let (status, result);
    if dst.is_null() {
        let input = unsafe { cstr_with_nul(start) };
        let (s, mut r, _) = count_towc(ps, input);
        if s == Status::Empty && r > 0 {
            r -= 1;
        }
        (status, result) = (s, r);
    } else {
        let out = unsafe { slice_mut(dst.cast::<u32>(), len.min(MAX_ELEMS)) };
        let mut pos = 0usize;
        let mut produced_total = 0usize;
        let mut s = Status::Full;
        while produced_total < out.len() {
            let chunk = unsafe { cstr_upto(start.wrapping_add(pos), out.len() - produced_total) };
            let (st2, used, produced) = towc(ps, chunk, &mut out[produced_total..]);
            produced_total += produced;
            pos += used;
            s = st2;
            if (st2 != Status::Empty && st2 != Status::Incomplete) || used != chunk.len() || chunk[used - 1] == 0 {
                break;
            }
        }
        let mut r = produced_total;
        let mut end = start.wrapping_add(pos);
        if s == Status::Empty && r > 0 && out[r - 1] == 0 {
            end = core::ptr::null();
            r -= 1;
        }
        unsafe { *src = end };
        (status, result) = (s, r);
    }
    if status == Status::Illegal {
        errno::set(EILSEQ);
        return ERR;
    }
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsrtowcs(dst: *mut wchar_t, src: *mut *const c_char, len: usize, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_MBSRTOWCS) };
    unsafe { mbsrtowcs_in(dst, src, len, st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsnrtowcs(dst: *mut wchar_t, src: *mut *const c_char, nmc: usize, len: usize, ps: *mut mbstate_t) -> usize {
    let ps = unsafe { state(ps, &S_MBSNRTOWCS) };
    if nmc == 0 {
        return 0;
    }
    let start = unsafe { *src };
    let input = unsafe { cstr_upto(start, nmc - 1) };
    let (status, result);
    if dst.is_null() {
        let (s, mut r, last) = count_towc(ps, input);
        if s == Status::Empty && last == 0 {
            r -= 1;
        }
        (status, result) = (s, r);
    } else {
        let out = unsafe { slice_mut(dst.cast::<u32>(), len.min(MAX_ELEMS)) };
        let (s, used, mut r) = towc(ps, input, out);
        let mut end = start.wrapping_add(used);
        if s == Status::Empty && r > 0 && out[r - 1] == 0 {
            end = core::ptr::null();
            r -= 1;
        }
        unsafe { *src = end };
        (status, result) = (s, r);
    }
    if status == Status::Illegal {
        errno::set(EILSEQ);
        return ERR;
    }
    result
}

fn count_tomb(st: &mbstate_t, src: &[u8], shifted: bool) -> (Status, usize, u8) {
    let mut temp = *st;
    let mut buf = [0u8; 256];
    let (mut pos, mut result, mut last) = (0usize, 0usize, 1u8);
    loop {
        let (s, used, produced) = if shifted {
            tomb_stateful(&mut temp, &src[pos..], &mut buf)
        } else {
            let (s, units, p) = tomb(&mut temp, &src[pos..], &mut buf);
            (s, units * 4, p)
        };
        pos += used;
        result += produced;
        if produced > 0 {
            last = buf[produced - 1];
        }
        if s != Status::Full {
            return (s, result, last);
        }
    }
}

unsafe fn wcsrtombs_core(dst: *mut c_char, src: *mut *const wchar_t, input: &[u8], len: usize, ps: &mut mbstate_t, shifted: bool, by_last: bool) -> usize {
    let (status, result);
    if dst.is_null() {
        let (s, mut r, last) = count_tomb(ps, input, shifted);
        if s == Status::Empty && (if by_last { last == 0 } else { r > 0 }) {
            r -= 1;
        }
        (status, result) = (s, r);
    } else {
        let out = unsafe { slice_mut(dst.cast::<u8>(), len.min(isize::MAX as usize)) };
        let (s, used, mut r) = if shifted {
            tomb_stateful(ps, input, out)
        } else {
            let (s, units, p) = tomb(ps, input, out);
            (s, units * 4, p)
        };
        let mut end = input.as_ptr().wrapping_add(used).cast::<wchar_t>();
        if s == Status::Empty && r > 0 && out[r - 1] == 0 {
            end = core::ptr::null();
            r -= 1;
        }
        unsafe { *src = end };
        (status, result) = (s, r);
    }
    if status == Status::Illegal || (shifted && status == Status::Incomplete) {
        errno::set(EILSEQ);
        return ERR;
    }
    result
}

unsafe fn wcsrtombs_in(dst: *mut c_char, src: *mut *const wchar_t, limit: Option<usize>, len: usize, ps: &mut mbstate_t) -> usize {
    let start = unsafe { *src };
    let w = unsafe { crate::wcstr::WStr::new(start) };
    let count = match limit {
        Some(nwc) => w.len_max(nwc - 1),
        None if dst.is_null() => w.len(),
        None => w.len_max(len),
    };
    let input = unsafe { rusty_libc_core::ffi::slice(w.as_ptr().cast::<u32>(), count + 1) };
    let shifted = ps.count & 7 != 0 && charset() == Charset::Utf8;
    if shifted && ps.count & 7 >= 4 {
        errno::set(EILSEQ);
        return ERR;
    }
    let by_last = shifted || limit.is_some();
    unsafe { wcsrtombs_core(dst, src, wide_bytes(input), len, ps, shifted, by_last) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrtombs(dst: *mut c_char, src: *mut *const wchar_t, len: usize, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_WCSRTOMBS) };
    unsafe { wcsrtombs_in(dst, src, None, len, st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnrtombs(dst: *mut c_char, src: *mut *const wchar_t, nwc: usize, len: usize, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_WCSNRTOMBS) };
    if nwc == 0 {
        return 0;
    }
    unsafe { wcsrtombs_in(dst, src, Some(nwc), len, st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbtowc(pwc: *mut wchar_t, s: *const c_char, n: usize) -> c_int {
    if s.is_null() {
        unsafe { S_MBTOWC.write(mbstate_t::default()) };
        return 0;
    }
    if unsafe { *s } == 0 {
        if let Some(w) = unsafe { out(pwc) } {
            *w = 0;
        }
        return 0;
    }
    let st = unsafe { state(core::ptr::null_mut(), &S_MBTOWC) };
    let r = unsafe { mbrtowc_in(pwc, s, n, st) };
    if r > usize::MAX - 2 { -1 } else { r as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mblen(s: *const c_char, n: usize) -> c_int {
    if s.is_null() {
        unsafe { S_MBRLEN.write(mbstate_t::default()) };
        return 0;
    }
    if unsafe { *s } == 0 {
        return 0;
    }
    let mut st = mbstate_t::default();
    let r = unsafe { mbrtowc_in(core::ptr::null_mut(), s, n, &mut st) };
    if r > usize::MAX - 2 { -1 } else { r as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctomb(s: *mut c_char, wc: wchar_t) -> c_int {
    if s.is_null() {
        unsafe { S_WCTOMB.write(mbstate_t::default()) };
        return 0;
    }
    let st = unsafe { state(core::ptr::null_mut(), &S_WCTOMB) };
    let r = unsafe { wcrtomb_in(s, wc, st) };
    if r == ERR { -1 } else { r as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbstowcs(pwcs: *mut wchar_t, s: *const c_char, n: usize) -> usize {
    let mut st = mbstate_t::default();
    let mut p = s;
    unsafe { mbsrtowcs_in(pwcs, &mut p, n, &mut st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstombs(s: *mut c_char, pwcs: *const wchar_t, n: usize) -> usize {
    let mut st = mbstate_t::default();
    let mut p = pwcs;
    unsafe { wcsrtombs_in(s, &mut p, None, n, &mut st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc32(pc32: *mut u32, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_MBRTOC32) };
    unsafe { mbrtowc_in(pc32.cast(), s, n, st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c32rtomb(s: *mut c_char, c32: u32, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_C32RTOMB) };
    unsafe { wcrtomb_in(s, c32 as wchar_t, st) }
}

const PENDING_BIT: i32 = i32::MIN;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc16(pc16: *mut u16, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_MBRTOC16) };
    let pc16 = unsafe { out(pc16) };
    if st.count & PENDING_BIT != 0 {
        st.count &= i32::MAX;
        if let Some(p) = pc16 {
            *p = st.value as u16;
        }
        st.value = 0;
        return PENDING;
    }
    let (pc16, s, n) = if s.is_null() { (None, c"".as_ptr(), 1) } else { (pc16, s, n) };
    let mut wc: wchar_t = 0;
    let r = unsafe { mbrtowc_in(&mut wc, s, n, st) };
    if r == ERR || r == INCOMPLETE {
        return r;
    }
    let wc = wc as u32;
    if wc < 0x10000 {
        if let Some(p) = pc16 {
            *p = wc as u16;
        }
    } else {
        if let Some(p) = pc16 {
            *p = (0xd7c0 + (wc >> 10)) as u16;
        }
        st.count |= PENDING_BIT;
        st.value = 0xdc00 + (wc & 0x3ff);
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c16rtomb(s: *mut c_char, c16: u16, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_C16RTOMB) };
    let mut wc = u32::from(c16);
    if s.is_null() {
        st.count &= i32::MAX;
        st.value = 0;
        wc = 0;
    }
    if st.count & PENDING_BIT != 0 {
        st.count &= i32::MAX;
        if (0xdc00..0xe000).contains(&wc) {
            wc = 0x10000 + ((st.value & 0x3ff) << 10) + (wc & 0x3ff);
        } else {
            wc = st.value;
        }
        st.value = 0;
    } else if (0xd800..0xdc00).contains(&wc) {
        st.count |= PENDING_BIT;
        st.value = wc;
        return 0;
    }
    unsafe { wcrtomb_in(s, wc as wchar_t, st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc8(pc8: *mut u8, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_MBRTOC8) };
    if st.count & PENDING_BIT != 0 {
        let mut v = st.value.to_le_bytes();
        let i = usize::from(v[3]);
        if let Some(p) = unsafe { out(pc8) } {
            *p = v[i.min(3)];
        }
        if i == 0 {
            st.count &= i32::MAX;
            st.value = 0;
        } else {
            v[3] -= 1;
            st.value = u32::from_le_bytes(v);
        }
        return PENDING;
    }
    let (pc8, s, n) = if s.is_null() { (core::ptr::null_mut(), c"".as_ptr(), 1) } else { (pc8, s, n) };
    let mut wc: wchar_t = 0;
    let r = unsafe { mbrtowc_in(&mut wc, s, n, st) };
    if r <= n {
        let wc = wc as u32;
        let mut v = st.value.to_le_bytes();
        let first;
        if wc <= 0x7f {
            first = wc as u8;
        } else if wc <= 0x7ff {
            first = 0xc0 + ((wc >> 6) & 0x1f) as u8;
            v[0] = 0x80 + (wc & 0x3f) as u8;
            v[3] = 0;
            st.count |= PENDING_BIT;
        } else if wc <= 0xffff {
            first = 0xe0 + ((wc >> 12) & 0x0f) as u8;
            v[1] = 0x80 + ((wc >> 6) & 0x3f) as u8;
            v[0] = 0x80 + (wc & 0x3f) as u8;
            v[3] = 1;
            st.count |= PENDING_BIT;
        } else if wc <= 0x10ffff {
            first = 0xf0 + ((wc >> 18) & 0x07) as u8;
            v[2] = 0x80 + ((wc >> 12) & 0x3f) as u8;
            v[1] = 0x80 + ((wc >> 6) & 0x3f) as u8;
            v[0] = 0x80 + (wc & 0x3f) as u8;
            v[3] = 2;
            st.count |= PENDING_BIT;
        } else {
            st.value = u32::from_le_bytes(v);
            return if r == 0 && wc != 0 { PENDING } else { r };
        }
        if let Some(p) = unsafe { out(pc8) } {
            *p = first;
        }
        st.value = u32::from_le_bytes(v);
    }
    if r == 0 && wc != 0 { PENDING } else { r }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c8rtomb(s: *mut c_char, c8: u8, ps: *mut mbstate_t) -> usize {
    let st = unsafe { state(ps, &S_C8RTOMB) };
    let c8 = if s.is_null() { 0 } else { c8 };
    let wc: u32;
    let mut v = st.value.to_le_bytes();
    if st.count & PENDING_BIT == 0 {
        if (0x80..=0xc1).contains(&c8) || c8 >= 0xf5 {
            errno::set(EILSEQ);
            return ERR;
        }
        if c8 >= 0xc2 {
            st.count |= PENDING_BIT;
            v[0] = c8;
            v[3] = 1;
            st.value = u32::from_le_bytes(v);
            return 0;
        }
        wc = u32::from(c8);
    } else {
        let cu1 = v[0];
        if v[3] == 1 {
            if !(0x80..=0xbf).contains(&c8) || (cu1 == 0xe0 && c8 < 0xa0) || (cu1 == 0xed && c8 > 0x9f) || (cu1 == 0xf0 && c8 < 0x90) || (cu1 == 0xf4 && c8 > 0x8f) {
                errno::set(EILSEQ);
                return ERR;
            }
            if cu1 >= 0xe0 {
                v[1] = c8;
                v[3] += 1;
                st.value = u32::from_le_bytes(v);
                return 0;
            }
            wc = (u32::from(cu1 & 0x1f) << 6) + u32::from(c8 & 0x3f);
        } else {
            let cu2 = v[1];
            if !(0x80..=0xbf).contains(&c8) {
                errno::set(EILSEQ);
                return ERR;
            }
            if v[3] == 2 && cu1 >= 0xf0 {
                v[2] = c8;
                v[3] += 1;
                st.value = u32::from_le_bytes(v);
                return 0;
            }
            if cu1 < 0xf0 {
                wc = (u32::from(cu1 & 0x0f) << 12) + (u32::from(cu2 & 0x3f) << 6) + u32::from(c8 & 0x3f);
            } else {
                let cu3 = v[2];
                wc = (u32::from(cu1 & 0x07) << 18) + (u32::from(cu2 & 0x3f) << 12) + (u32::from(cu3 & 0x3f) << 6) + u32::from(c8 & 0x3f);
            }
        }
        st.count &= i32::MAX;
        st.value = 0;
    }
    unsafe { wcrtomb_in(s, wc as wchar_t, st) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded {
    Char(u32, usize),
    Incomplete,
    Invalid,
}

fn decoded(status: Status, used: usize, produced: usize, w: u32) -> Decoded {
    match status {
        Status::Empty | Status::Full if produced == 1 => Decoded::Char(w, used),
        Status::Incomplete => Decoded::Incomplete,
        _ => Decoded::Invalid,
    }
}

pub fn decode_char(bytes: &[u8], state: &mut mbstate_t) -> Decoded {
    if bytes.is_empty() {
        return Decoded::Incomplete;
    }
    let mut w = 0u32;
    let (status, used, produced) = towc(state, bytes, core::slice::from_mut(&mut w));
    decoded(status, used, produced, w)
}

pub fn decode_cs(cs: Charset, bytes: &[u8]) -> Decoded {
    if bytes.is_empty() {
        return Decoded::Incomplete;
    }
    let mut st = mbstate_t::default();
    let mut w = 0u32;
    let (status, used, produced) = towc_cs(cs, &mut st, bytes, core::slice::from_mut(&mut w));
    decoded(status, used, produced, w)
}

pub fn encode_cs(cs: Charset, wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    match cs {
        Charset::Other => other_encode(wc, out),
        Charset::Utf8 => encode_utf8(wc, out),
        Charset::C => {
            out[0] = wc as u8;
            if wc <= 0x7f { Some(1) } else { None }
        }
    }
}

pub fn encode_char(wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    encode_cs(charset(), wc, out)
}

pub fn to_wide(src: &[u8], dst: &mut [u32]) -> Result<usize, usize> {
    let mut st = mbstate_t::default();
    let (mut pos, mut n) = (0usize, 0usize);
    while pos < src.len() && src[pos] != 0 && n < dst.len() {
        match decode_char(&src[pos..], &mut st) {
            Decoded::Char(c, used) => {
                dst[n] = c;
                n += 1;
                pos += used;
            }
            _ => return Err(pos),
        }
    }
    if n < dst.len() {
        dst[n] = 0;
    }
    Ok(n)
}

pub fn to_multibyte(src: &[u32], dst: &mut [u8]) -> Result<usize, usize> {
    let mut n = 0usize;
    for (i, &c) in src.iter().enumerate() {
        if c == 0 {
            break;
        }
        let mut b = [0u8; 6];
        let Some(l) = encode_char(c, &mut b) else { return Err(i) };
        if n + l > dst.len() {
            break;
        }
        dst[n..n + l].copy_from_slice(&b[..l]);
        n += l;
    }
    if n < dst.len() {
        dst[n] = 0;
    }
    Ok(n)
}

