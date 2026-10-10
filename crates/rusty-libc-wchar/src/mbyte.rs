use crate::{Charset, charset, mbstate_t, wchar_t, wint_t, WEOF};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use rusty_libc_core::errno;

pub const EILSEQ: i32 = 84;
pub const MB_LEN_MAX: usize = 16;

const ERR: usize = usize::MAX;
const INCOMPLETE: usize = usize::MAX - 1;
const PENDING: usize = usize::MAX - 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Empty,
    Full,
    Illegal,
    Incomplete,
}

struct Hidden(UnsafeCell<mbstate_t>);
unsafe impl Sync for Hidden {}
impl Hidden {
    const fn new() -> Hidden {
        Hidden(UnsafeCell::new(mbstate_t { count: 0, value: 0 }))
    }
}

static S_MBRTOWC: Hidden = Hidden::new();
static S_MBRLEN: Hidden = Hidden::new();
static S_MBSRTOWCS: Hidden = Hidden::new();
static S_MBSNRTOWCS: Hidden = Hidden::new();
static S_WCRTOMB: Hidden = Hidden::new();
static S_WCSRTOMBS: Hidden = Hidden::new();
static S_WCSNRTOMBS: Hidden = Hidden::new();
static S_MBTOWC: Hidden = Hidden::new();
static S_WCTOMB: Hidden = Hidden::new();
static S_MBRTOC8: Hidden = Hidden::new();
static S_C8RTOMB: Hidden = Hidden::new();
static S_MBRTOC16: Hidden = Hidden::new();
static S_C16RTOMB: Hidden = Hidden::new();
static S_MBRTOC32: Hidden = Hidden::new();
static S_C32RTOMB: Hidden = Hidden::new();

fn pick(ps: *mut mbstate_t, own: &Hidden) -> *mut mbstate_t {
    if ps.is_null() { own.0.get() } else { ps }
}

enum Dec {
    Ok(u32, usize),
    Incomplete,
    Illegal,
}

unsafe fn decode(p: *const u8, avail: usize) -> Dec {
    unsafe {
        let b0 = *p;
        if b0 < 0x80 {
            return Dec::Ok(u32::from(b0), 1);
        }
        let (cnt, mask) = match b0 {
            0xc2..=0xdf => (2usize, 0x1fu8),
            0xe0..=0xef => (3, 0x0f),
            0xf0..=0xf7 => (4, 0x07),
            0xf8..=0xfb => (5, 0x03),
            0xfc..=0xfd => (6, 0x01),
            _ => return Dec::Illegal,
        };
        if avail < cnt {
            for i in 1..avail {
                if *p.add(i) & 0xc0 != 0x80 {
                    return Dec::Illegal;
                }
            }
            return Dec::Incomplete;
        }
        let mut ch = u32::from(b0 & mask);
        for i in 1..cnt {
            let b = *p.add(i);
            if b & 0xc0 != 0x80 {
                return Dec::Illegal;
            }
            ch = (ch << 6) | u32::from(b & 0x3f);
        }
        if (cnt > 2 && (ch >> (5 * cnt - 4)) == 0) || (0xd800..=0xdfff).contains(&ch) {
            return Dec::Illegal;
        }
        Dec::Ok(ch, cnt)
    }
}

unsafe fn store_rest(st: &mut mbstate_t, p: *const u8, m: usize) {
    unsafe {
        let lead = *p;
        let (cnt, mask) = match lead {
            0xc2..=0xdf => (2usize, 0x1fu8),
            0xe0..=0xef => (3, 0x0f),
            0xf0..=0xf7 => (4, 0x07),
            0xf8..=0xfb => (5, 0x03),
            _ => (6, 0x01),
        };
        let mut ch = u32::from(lead & mask);
        for i in 1..m {
            ch = (ch << 6) | u32::from(*p.add(i) & 0x3f);
        }
        let r = cnt - m;
        ch = ch.wrapping_shl((r * 6) as u32);
        st.count = m as i32 | ((cnt as i32) << 8);
        st.value = ch;
    }
}

unsafe fn utf8_towc(st: &mut mbstate_t, src: &mut *const u8, mut avail: usize, out: *mut u32, cap: usize) -> (Status, usize) {
    unsafe {
        let mut produced = 0usize;
        if st.count & 7 != 0 {
            let inlen = (st.count & 255) as usize;
            let ntotal = (st.count as u32 >> 8) as usize;
            if !(2..=6).contains(&ntotal) || inlen == 0 || inlen >= ntotal {
                return (Status::Illegal, 0);
            }
            if cap == 0 {
                return (Status::Full, 0);
            }
            if avail == 0 {
                return (Status::Empty, 0);
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
            let mut total = inlen;
            let mut taken = 0;
            while total < 6 && taken < avail {
                buf[total] = *(*src).add(taken);
                total += 1;
                taken += 1;
            }
            match decode(buf.as_ptr(), total) {
                Dec::Ok(ch, cnt) => {
                    let used = cnt.saturating_sub(inlen);
                    *src = (*src).add(used);
                    avail -= used;
                    *out = ch;
                    produced = 1;
                    st.count = 0;
                }
                Dec::Incomplete => {
                    *src = (*src).add(taken);
                    store_rest(st, buf.as_ptr(), total);
                    return (Status::Incomplete, 0);
                }
                Dec::Illegal => return (Status::Illegal, 0),
            }
        }
        loop {
            if avail == 0 {
                return (Status::Empty, produced);
            }
            if produced == cap {
                return (Status::Full, produced);
            }
            match decode(*src, avail) {
                Dec::Ok(ch, cnt) => {
                    *out.add(produced) = ch;
                    produced += 1;
                    *src = (*src).add(cnt);
                    avail -= cnt;
                }
                Dec::Incomplete => {
                    store_rest(st, *src, avail);
                    *src = (*src).add(avail);
                    return (Status::Incomplete, produced);
                }
                Dec::Illegal => return (Status::Illegal, produced),
            }
        }
    }
}

unsafe fn ascii_towc(src: &mut *const u8, mut avail: usize, out: *mut u32, cap: usize) -> (Status, usize) {
    unsafe {
        let mut produced = 0;
        loop {
            if avail == 0 {
                return (Status::Empty, produced);
            }
            if produced == cap {
                return (Status::Full, produced);
            }
            let b = **src;
            if b > 0x7f {
                return (Status::Illegal, produced);
            }
            *out.add(produced) = u32::from(b);
            produced += 1;
            *src = (*src).add(1);
            avail -= 1;
        }
    }
}

unsafe fn towc(st: &mut mbstate_t, src: &mut *const u8, avail: usize, out: *mut u32, cap: usize) -> (Status, usize) {
    unsafe {
        match charset() {
            Charset::Utf8 => utf8_towc(st, src, avail, out, cap),
            Charset::C => ascii_towc(src, avail, out, cap),
            Charset::Other => other_towc(st, src, avail, out, cap),
        }
    }
}

pub fn codeset_name() -> ([u8; 48], usize) {
    let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE);
    let mut b = [0u8; 48];
    if d.is_null() {
        return (b, 0);
    }
    let s = unsafe { (*d).bytes(14) };
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

unsafe fn other_towc(st: &mut mbstate_t, src: &mut *const u8, avail: usize, out: *mut u32, cap: usize) -> (Status, usize) {
    let f = OTHER_TOWC.load(Ordering::Acquire);
    if f == 0 {
        return (Status::Illegal, 0);
    }
    let f: OtherToWc = unsafe { core::mem::transmute::<usize, OtherToWc>(f) };
    unsafe { f(st, src, avail, out, cap) }
}

unsafe fn other_tomb(st: &mut mbstate_t, src: &mut *const u32, avail: usize, out: *mut u8, cap: usize) -> (Status, usize) {
    let f = OTHER_TOMB.load(Ordering::Acquire);
    if f == 0 {
        return (Status::Illegal, 0);
    }
    let f: OtherToMb = unsafe { core::mem::transmute::<usize, OtherToMb>(f) };
    unsafe { f(st, src, avail, out, cap) }
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

unsafe fn tomb(st: &mut mbstate_t, src: &mut *const u32, mut avail: usize, out: *mut u8, cap: usize) -> (Status, usize) {
    unsafe {
        if charset() == Charset::Other {
            if avail != 0 && cap == 0 {
                return (Status::Full, 0);
            }
            return other_tomb(st, src, avail, out, cap);
        }
        let mut produced = 0usize;
        loop {
            while avail >= 4 && cap - produced >= 4 {
                let p = *src;
                let (a, b, c, d) = (p.read_unaligned(), p.add(1).read_unaligned(), p.add(2).read_unaligned(), p.add(3).read_unaligned());
                if (a | b | c | d) >= 0x80 {
                    break;
                }
                (out.add(produced) as *mut u32).write_unaligned(a | (b << 8) | (c << 16) | (d << 24));
                produced += 4;
                *src = p.add(4);
                avail -= 4;
            }
            while avail != 0 && produced < cap {
                let wc = (*src).read_unaligned();
                if wc >= 0x80 {
                    break;
                }
                *out.add(produced) = wc as u8;
                produced += 1;
                *src = (*src).add(1);
                avail -= 1;
            }
            if avail == 0 {
                return (Status::Empty, produced);
            }
            if produced >= cap {
                return (Status::Full, produced);
            }
            let wc = (*src).read_unaligned();
            let mut b = [0u8; 6];
            let n = match charset() {
                Charset::Utf8 => encode_utf8(wc, &mut b),
                Charset::C => {
                    b[0] = wc as u8;
                    if wc <= 0x7f { Some(1) } else { None }
                }
                Charset::Other => other_encode(wc, &mut b),
            };
            let Some(n) = n else {
                if (wc >> 7) == (0xe0000 >> 7) {
                    *src = (*src).add(1);
                    avail -= 1;
                    continue;
                }
                return (Status::Illegal, produced);
            };
            if produced + n > cap {
                return (Status::Full, produced);
            }
            core::ptr::copy_nonoverlapping(b.as_ptr(), out.add(produced), n);
            produced += n;
            *src = (*src).add(1);
            avail -= 1;
        }
    }
}

unsafe fn tomb_stateful(ps: &mut mbstate_t, src: &mut *const u32, avail: &mut usize, out: *mut u8, cap: usize) -> (Status, usize) {
    unsafe {
        let mut produced = 0usize;
        let n = (ps.count & 7) as usize;
        if n != 0 {
            let need = 4 - n;
            if produced >= cap {
                return (Status::Full, 0);
            }
            if *avail < need {
                let mut bytes = ps.value.to_le_bytes();
                for i in 0..*avail {
                    bytes[n + i] = *(*src as *const u8).add(i);
                }
                ps.value = u32::from_le_bytes(bytes);
                ps.count = (ps.count & !7) | (n + *avail) as i32;
                *src = (*src as *const u8).add(*avail) as *const u32;
                *avail = 0;
                return (Status::Incomplete, 0);
            }
            let mut bytes = ps.value.to_le_bytes();
            for i in 0..need {
                bytes[n + i] = *(*src as *const u8).add(i);
            }
            let wc = u32::from_le_bytes(bytes);
            let mut b = [0u8; 6];
            let Some(len) = encode_utf8(wc, &mut b) else { return (Status::Illegal, 0) };
            if len > cap {
                return (Status::Full, 0);
            }
            core::ptr::copy_nonoverlapping(b.as_ptr(), out, len);
            produced = len;
            ps.count &= !7;
            *src = (*src as *const u8).add(need) as *const u32;
            *avail -= need;
        }
        let units = *avail / 4;
        let before = *src;
        let (status, p) = tomb(ps, src, units, out.add(produced), cap - produced);
        produced += p;
        *avail -= (*src as usize - before as usize) / 4 * 4;
        if status == Status::Empty && *avail != 0 {
            let tail = *avail;
            let mut bytes = ps.value.to_le_bytes();
            for (i, b) in bytes.iter_mut().enumerate().take(tail) {
                *b = *(*src as *const u8).add(i);
            }
            ps.value = u32::from_le_bytes(bytes);
            ps.count = (ps.count & !7) | tail as i32;
            *src = (*src as *const u8).add(tail) as *const u32;
            *avail = 0;
            return (Status::Incomplete, produced);
        }
        (status, produced)
    }
}

unsafe fn mbrtowc_in(pwc: *mut wchar_t, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    unsafe {
        let st = &mut *ps;
        let mut buf = 0u32;
        let (out, s, n) = if s.is_null() { (&raw mut buf, c"".as_ptr(), 1) } else { (if pwc.is_null() { &raw mut buf } else { pwc as *mut u32 }, s, n) };
        if n == 0 {
            return INCOMPLETE;
        }
        let mut p = s as *const u8;
        let (status, produced) = towc(st, &mut p, n, out, 1);
        match status {
            Status::Empty | Status::Full => {
                if produced > 0 && *out == 0 {
                    0
                } else {
                    p as usize - s as usize
                }
            }
            Status::Incomplete => INCOMPLETE,
            Status::Illegal => {
                errno::set(EILSEQ);
                ERR
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtowc(pwc: *mut wchar_t, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    unsafe { mbrtowc_in(pwc, s, n, pick(ps, &S_MBRTOWC)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbrlen(s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    unsafe { mbrlen(s, n, ps) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrlen(s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    unsafe { mbrtowc_in(core::ptr::null_mut(), s, n, pick(ps, &S_MBRLEN)) }
}

unsafe fn wcrtomb_in(s: *mut c_char, wc: wchar_t, ps: *mut mbstate_t) -> usize {
    unsafe {
        let st = &mut *ps;
        let mut wc = wc as u32;
        if s.is_null() {
            wc = 0;
        }
        let mut buf = [0u8; MB_LEN_MAX];
        let n = if wc == 0 {
            let produced = if charset() == Charset::Other && (st.count & !7) != 0 {
                let mut p = &wc as *const u32;
                tomb(st, &mut p, 1, buf.as_mut_ptr(), MB_LEN_MAX).1
            } else {
                buf[0] = 0;
                1
            };
            *st = mbstate_t::default();
            produced
        } else if charset() == Charset::Utf8 && st.count & 7 != 0 {
            let k = (st.count & 7) as usize;
            if k > 3 {
                errno::set(EILSEQ);
                return ERR;
            }
            let mut four = [0u8; 4];
            four[..k].copy_from_slice(&st.value.to_le_bytes()[..k]);
            four[k..].copy_from_slice(&wc.to_le_bytes()[..4 - k]);
            let mut e = [0u8; 6];
            if encode_utf8(u32::from_le_bytes(four), &mut e).is_none() {
                errno::set(EILSEQ);
                return ERR;
            }
            let mut v = st.value.to_le_bytes();
            v[..k].copy_from_slice(&wc.to_le_bytes()[4 - k..]);
            st.value = u32::from_le_bytes(v);
            st.count = (st.count & !7) | k as i32;
            errno::set(EILSEQ);
            return ERR;
        } else {
            let mut p = &wc as *const u32;
            let (status, produced) = tomb(st, &mut p, 1, buf.as_mut_ptr(), MB_LEN_MAX);
            if status == Status::Illegal || status == Status::Incomplete {
                errno::set(EILSEQ);
                return ERR;
            }
            produced
        };
        if !s.is_null() {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), s as *mut u8, n);
        }
        n
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcrtomb(s: *mut c_char, wc: wchar_t, ps: *mut mbstate_t) -> usize {
    unsafe { wcrtomb_in(s, wc, pick(ps, &S_WCRTOMB)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsinit(ps: *const mbstate_t) -> c_int {
    unsafe { c_int::from(ps.is_null() || (*ps).count == 0) }
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
        let b = c as u8;
        let mut p = &b as *const u8;
        let (status, produced) = unsafe { other_towc(&mut st, &mut p, 1, &mut w, 1) };
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
            let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE);
            if d.is_null() { 1 } else { (unsafe { (*d).word(13) } as usize).max(1) }
        }
    }
}

unsafe fn strlen(s: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(s) }
}

unsafe fn strnlen(s: *const c_char, n: usize) -> usize {
    unsafe { rusty_libc_mem::strnlen(s, n) }
}

unsafe fn wcslen(s: *const wchar_t) -> usize {
    unsafe { crate::wstring::wcslen(s) }
}

unsafe fn wcsnlen(s: *const wchar_t, n: usize) -> usize {
    unsafe { crate::wstring::wcsnlen(s, n) }
}

unsafe fn mbsrtowcs_in(dst: *mut wchar_t, src: *mut *const c_char, len: usize, ps: *mut mbstate_t) -> usize {
    unsafe {
        let mut result;
        let mut status;
        if dst.is_null() {
            let mut temp = *ps;
            let mut buf = [0u32; 64];
            let mut inbuf = *src as *const u8;
            let srcend_len = strlen(*src) + 1;
            let mut avail = srcend_len;
            result = 0;
            loop {
                let (s, produced) = towc(&mut temp, &mut inbuf, avail, buf.as_mut_ptr(), 64);
                avail = srcend_len - (inbuf as usize - *src as usize);
                result += produced;
                status = s;
                if s != Status::Full {
                    break;
                }
            }
            if status == Status::Empty && result > 0 {
                result -= 1;
            }
        } else {
            let mut srcp = *src as *const u8;
            let mut len_rem = len;
            let mut produced_total = 0usize;
            status = Status::Full;
            let cap = len;
            let out = dst as *mut u32;
            while len_rem > 0 {
                let chunk = strnlen(srcp as *const c_char, len_rem) + 1;
                let start = srcp;
                let (s, produced) = towc(&mut *ps, &mut srcp, chunk, out.add(produced_total), cap - produced_total);
                produced_total += produced;
                status = s;
                let used = srcp as usize - start as usize;
                if (s != Status::Empty && s != Status::Incomplete) || used != chunk || *srcp.sub(1) == 0 {
                    break;
                }
                len_rem = cap - produced_total;
            }
            *src = srcp as *const c_char;
            result = produced_total;
            if status == Status::Empty && result > 0 && *(dst as *mut u32).add(result - 1) == 0 {
                *src = core::ptr::null();
                result -= 1;
            }
        }
        if status == Status::Illegal {
            errno::set(EILSEQ);
            return ERR;
        }
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsrtowcs(dst: *mut wchar_t, src: *mut *const c_char, len: usize, ps: *mut mbstate_t) -> usize {
    unsafe { mbsrtowcs_in(dst, src, len, pick(ps, &S_MBSRTOWCS)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsnrtowcs(dst: *mut wchar_t, src: *mut *const c_char, nmc: usize, len: usize, ps: *mut mbstate_t) -> usize {
    unsafe {
        let ps = pick(ps, &S_MBSNRTOWCS);
        if nmc == 0 {
            return 0;
        }
        let avail_total = strnlen(*src, nmc - 1) + 1;
        let status;
        let mut result;
        if dst.is_null() {
            let mut temp = *ps;
            let mut buf = [0u32; 64];
            let mut inbuf = *src as *const u8;
            let mut avail = avail_total;
            result = 0;
            let mut last = 1u32;
            loop {
                let (s, produced) = towc(&mut temp, &mut inbuf, avail, buf.as_mut_ptr(), 64);
                avail = avail_total - (inbuf as usize - *src as usize);
                result += produced;
                if produced > 0 {
                    last = buf[produced - 1];
                }
                if s != Status::Full {
                    status = s;
                    break;
                }
            }
            if status == Status::Empty && last == 0 {
                result -= 1;
            }
        } else {
            let mut p = *src as *const u8;
            let (s, produced) = towc(&mut *ps, &mut p, avail_total, dst as *mut u32, len);
            status = s;
            *src = p as *const c_char;
            result = produced;
            if status == Status::Empty && result > 0 && *(dst as *mut u32).add(result - 1) == 0 {
                *src = core::ptr::null();
                result -= 1;
            }
        }
        if status == Status::Illegal {
            errno::set(EILSEQ);
            return ERR;
        }
        result
    }
}

unsafe fn wcsrtombs_shifted(dst: *mut c_char, src: *mut *const wchar_t, total: usize, len: usize, ps: *mut mbstate_t) -> usize {
    unsafe {
        let status;
        let mut result;
        if (*ps).count & 7 >= 4 {
            errno::set(EILSEQ);
            return ERR;
        }
        if dst.is_null() {
            let mut temp = *ps;
            let mut buf = [0u8; 256];
            let mut p = *src as *const u32;
            let mut avail = total * 4;
            result = 0;
            let mut last = 1u8;
            loop {
                let (s, produced) = tomb_stateful(&mut temp, &mut p, &mut avail, buf.as_mut_ptr(), 256);
                result += produced;
                if produced > 0 {
                    last = buf[produced - 1];
                }
                if s != Status::Full {
                    status = s;
                    break;
                }
            }
            if status == Status::Empty && last == 0 {
                result -= 1;
            }
        } else {
            let mut p = *src as *const u32;
            let mut avail = total * 4;
            let (s, produced) = tomb_stateful(&mut *ps, &mut p, &mut avail, dst as *mut u8, len);
            status = s;
            *src = p as *const wchar_t;
            result = produced;
            if status == Status::Empty && result > 0 && *dst.add(result - 1) == 0 {
                *src = core::ptr::null();
                result -= 1;
            }
        }
        if status == Status::Illegal || status == Status::Incomplete {
            errno::set(EILSEQ);
            return ERR;
        }
        result
    }
}

unsafe fn wcsrtombs_in(dst: *mut c_char, src: *mut *const wchar_t, len: usize, ps: *mut mbstate_t) -> usize {
    unsafe {
        if (*ps).count & 7 != 0 && charset() == Charset::Utf8 {
            let total = if dst.is_null() { wcslen(*src) + 1 } else { wcsnlen(*src, len) + 1 };
            return wcsrtombs_shifted(dst, src, total, len, ps);
        }
        let status;
        let mut result;
        if dst.is_null() {
            let mut buf = [0u8; 256];
            let mut temp = *ps;
            let total = wcslen(*src) + 1;
            let mut p = *src as *const u32;
            let mut avail = total;
            result = 0;
            loop {
                let (s, produced) = tomb(&mut temp, &mut p, avail, buf.as_mut_ptr(), 256);
                avail = total - (p as usize - *src as usize) / 4;
                result += produced;
                if s != Status::Full {
                    status = s;
                    break;
                }
            }
            if status == Status::Empty && result > 0 {
                result -= 1;
            }
        } else {
            let total = wcsnlen(*src, len) + 1;
            let mut p = *src as *const u32;
            let (s, produced) = tomb(&mut *ps, &mut p, total, dst as *mut u8, len);
            status = s;
            *src = p as *const wchar_t;
            result = produced;
            if status == Status::Empty && result > 0 && *dst.add(result - 1) == 0 {
                *src = core::ptr::null();
                result -= 1;
            }
        }
        if status == Status::Illegal {
            errno::set(EILSEQ);
            return ERR;
        }
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrtombs(dst: *mut c_char, src: *mut *const wchar_t, len: usize, ps: *mut mbstate_t) -> usize {
    unsafe { wcsrtombs_in(dst, src, len, pick(ps, &S_WCSRTOMBS)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnrtombs(dst: *mut c_char, src: *mut *const wchar_t, nwc: usize, len: usize, ps: *mut mbstate_t) -> usize {
    unsafe {
        let ps = pick(ps, &S_WCSNRTOMBS);
        if nwc == 0 {
            return 0;
        }
        let total = wcsnlen(*src, nwc - 1) + 1;
        if (*ps).count & 7 != 0 && charset() == Charset::Utf8 {
            return wcsrtombs_shifted(dst, src, total, len, ps);
        }
        let status;
        let mut result;
        if dst.is_null() {
            let mut buf = [0u8; 256];
            let mut temp = *ps;
            let mut p = *src as *const u32;
            let mut avail = total;
            result = 0;
            let mut last = 1u8;
            loop {
                let (s, produced) = tomb(&mut temp, &mut p, avail, buf.as_mut_ptr(), 256);
                avail = total - (p as usize - *src as usize) / 4;
                result += produced;
                if produced > 0 {
                    last = buf[produced - 1];
                }
                if s != Status::Full {
                    status = s;
                    break;
                }
            }
            if status == Status::Empty && last == 0 {
                result -= 1;
            }
        } else {
            let mut p = *src as *const u32;
            let (s, produced) = tomb(&mut *ps, &mut p, total, dst as *mut u8, len);
            status = s;
            *src = p as *const wchar_t;
            result = produced;
            if status == Status::Empty && result > 0 && *dst.add(result - 1) == 0 {
                *src = core::ptr::null();
                result -= 1;
            }
        }
        if status == Status::Illegal {
            errno::set(EILSEQ);
            return ERR;
        }
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbtowc(pwc: *mut wchar_t, s: *const c_char, n: usize) -> c_int {
    unsafe {
        if s.is_null() {
            *S_MBTOWC.0.get() = mbstate_t::default();
            return 0;
        }
        if *s == 0 {
            if !pwc.is_null() {
                *pwc = 0;
            }
            return 0;
        }
        let r = mbrtowc_in(pwc, s, n, S_MBTOWC.0.get());
        if r > usize::MAX - 2 { -1 } else { r as c_int }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mblen(s: *const c_char, n: usize) -> c_int {
    unsafe {
        if s.is_null() {
            *S_MBRLEN.0.get() = mbstate_t::default();
            return 0;
        }
        if *s == 0 {
            return 0;
        }
        let mut st = mbstate_t::default();
        let r = mbrtowc_in(core::ptr::null_mut(), s, n, &mut st);
        if r > usize::MAX - 2 { -1 } else { r as c_int }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctomb(s: *mut c_char, wc: wchar_t) -> c_int {
    unsafe {
        if s.is_null() {
            *S_WCTOMB.0.get() = mbstate_t::default();
            return 0;
        }
        let r = wcrtomb_in(s, wc, S_WCTOMB.0.get());
        if r == ERR { -1 } else { r as c_int }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbstowcs(pwcs: *mut wchar_t, s: *const c_char, n: usize) -> usize {
    unsafe {
        let mut st = mbstate_t::default();
        let mut p = s;
        mbsrtowcs_in(pwcs, &mut p, n, &mut st)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstombs(s: *mut c_char, pwcs: *const wchar_t, n: usize) -> usize {
    unsafe {
        let mut st = mbstate_t::default();
        let mut p = pwcs;
        wcsrtombs_in(s, &mut p, n, &mut st)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc32(pc32: *mut u32, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    unsafe { mbrtowc_in(pc32 as *mut wchar_t, s, n, pick(ps, &S_MBRTOC32)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c32rtomb(s: *mut c_char, c32: u32, ps: *mut mbstate_t) -> usize {
    unsafe { wcrtomb_in(s, c32 as wchar_t, pick(ps, &S_C32RTOMB)) }
}

const PENDING_BIT: i32 = i32::MIN;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc16(pc16: *mut u16, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    unsafe {
        let ps = pick(ps, &S_MBRTOC16);
        let st = &mut *ps;
        if st.count & PENDING_BIT != 0 {
            st.count &= i32::MAX;
            if !pc16.is_null() {
                *pc16 = st.value as u16;
            }
            st.value = 0;
            return PENDING;
        }
        let (pc16, s, n) = if s.is_null() { (core::ptr::null_mut(), c"".as_ptr(), 1) } else { (pc16, s, n) };
        let mut wc: wchar_t = 0;
        let r = mbrtowc_in(&mut wc, s, n, ps);
        if r == ERR || r == INCOMPLETE {
            return r;
        }
        let wc = wc as u32;
        if wc < 0x10000 {
            if !pc16.is_null() {
                *pc16 = wc as u16;
            }
        } else {
            if !pc16.is_null() {
                *pc16 = (0xd7c0 + (wc >> 10)) as u16;
            }
            st.count |= PENDING_BIT;
            st.value = 0xdc00 + (wc & 0x3ff);
        }
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c16rtomb(s: *mut c_char, c16: u16, ps: *mut mbstate_t) -> usize {
    unsafe {
        let ps = pick(ps, &S_C16RTOMB);
        let st = &mut *ps;
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
        wcrtomb_in(s, wc as wchar_t, ps)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc8(pc8: *mut u8, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    unsafe {
        let ps = pick(ps, &S_MBRTOC8);
        let st = &mut *ps;
        if st.count & PENDING_BIT != 0 {
            let mut v = st.value.to_le_bytes();
            let i = usize::from(v[3]);
            if !pc8.is_null() {
                *pc8 = v[i.min(3)];
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
        let r = mbrtowc_in(&mut wc, s, n, ps);
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
            if !pc8.is_null() && (wc <= 0x10ffff) {
                *pc8 = first;
            }
            st.value = u32::from_le_bytes(v);
        }
        if r == 0 && wc != 0 { PENDING } else { r }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c8rtomb(s: *mut c_char, c8: u8, ps: *mut mbstate_t) -> usize {
    unsafe {
        let ps = pick(ps, &S_C8RTOMB);
        let st = &mut *ps;
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
        wcrtomb_in(s, wc as wchar_t, ps)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded {
    Char(u32, usize),
    Incomplete,
    Invalid,
}

pub fn decode_char(bytes: &[u8], state: &mut mbstate_t) -> Decoded {
    if bytes.is_empty() {
        return Decoded::Incomplete;
    }
    let mut w = 0u32;
    let mut p = bytes.as_ptr();
    let (status, produced) = unsafe { towc(state, &mut p, bytes.len(), &mut w, 1) };
    match status {
        Status::Empty | Status::Full if produced == 1 => Decoded::Char(w, p as usize - bytes.as_ptr() as usize),
        Status::Incomplete => Decoded::Incomplete,
        _ => Decoded::Invalid,
    }
}

pub fn decode_cs(cs: Charset, bytes: &[u8]) -> Decoded {
    if bytes.is_empty() {
        return Decoded::Incomplete;
    }
    let mut st = mbstate_t::default();
    let mut w = 0u32;
    let mut p = bytes.as_ptr();
    let (status, produced) = unsafe {
        match cs {
            Charset::Utf8 => utf8_towc(&mut st, &mut p, bytes.len(), &mut w, 1),
            Charset::C => ascii_towc(&mut p, bytes.len(), &mut w, 1),
            Charset::Other => other_towc(&mut st, &mut p, bytes.len(), &mut w, 1),
        }
    };
    match status {
        Status::Empty | Status::Full if produced == 1 => Decoded::Char(w, p as usize - bytes.as_ptr() as usize),
        Status::Incomplete => Decoded::Incomplete,
        _ => Decoded::Invalid,
    }
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
    match charset() {
        Charset::Other => other_encode(wc, out),
        Charset::Utf8 => encode_utf8(wc, out),
        Charset::C => {
            out[0] = wc as u8;
            if wc <= 0x7f { Some(1) } else { None }
        }
    }
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

