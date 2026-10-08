use crate::float;
use rusty_libc_core::errno;

const EINVAL: i32 = 22;
const EOVERFLOW: i32 = 75;
const EILSEQ: i32 = 84;

pub trait FmtChar: Copy {
    const WIDE: bool;
    unsafe fn at(p: *const Self, i: usize) -> u8;
    unsafe fn raw(p: *const Self, i: usize) -> u32;
    unsafe fn emit_run<S: Sink>(o: &mut Out<S>, p: *const Self, start: usize, len: usize);
    unsafe fn has_dollar(p: *const Self) -> bool;
    fn from_ascii(b: u8) -> Self;
}

impl FmtChar for u8 {
    const WIDE: bool = false;
    #[inline(always)]
    fn from_ascii(b: u8) -> u8 {
        b
    }
    #[inline(always)]
    unsafe fn at(p: *const u8, i: usize) -> u8 {
        unsafe { *p.add(i) }
    }
    #[inline(always)]
    unsafe fn raw(p: *const u8, i: usize) -> u32 {
        unsafe { u32::from(*p.add(i)) }
    }
    #[inline(always)]
    unsafe fn emit_run<S: Sink>(o: &mut Out<S>, p: *const u8, start: usize, len: usize) {
        unsafe { o.put(core::slice::from_raw_parts(p.add(start), len)) }
    }
    #[inline(always)]
    unsafe fn has_dollar(p: *const u8) -> bool {
        unsafe {
            const ONES: u64 = 0x0101_0101_0101_0101;
            const HIGH: u64 = 0x8080_8080_8080_8080;
            let addr = p as usize;
            let mut q = (addr & !7) as *const u64;
            let mut w = core::ptr::read_volatile(q) | ((1u64 << ((addr & 7) * 8)) - 1);
            for _ in 0..4 {
                let hit = (w.wrapping_sub(ONES) & !w & HIGH) | ((w ^ (ONES * 0x24)).wrapping_sub(ONES) & !(w ^ (ONES * 0x24)) & HIGH);
                if hit != 0 {
                    let byte = (w >> (hit.trailing_zeros() & !7)) as u8;
                    return byte == b'$';
                }
                q = q.add(1);
                w = core::ptr::read_volatile(q);
            }
            !rusty_libc_mem::strchr(q as *const core::ffi::c_char, b'$' as i32).is_null()
        }
    }
}

impl FmtChar for u32 {
    const WIDE: bool = true;
    #[inline(always)]
    fn from_ascii(b: u8) -> u32 {
        u32::from(b)
    }
    #[inline(always)]
    unsafe fn at(p: *const u32, i: usize) -> u8 {
        unsafe {
            let c = *p.add(i);
            if c < 0x80 { c as u8 } else { 0xff }
        }
    }
    #[inline(always)]
    unsafe fn raw(p: *const u32, i: usize) -> u32 {
        unsafe { *p.add(i) }
    }
    #[inline(always)]
    unsafe fn emit_run<S: Sink>(o: &mut Out<S>, p: *const u32, start: usize, len: usize) {
        unsafe { o.put_w(core::slice::from_raw_parts(p.add(start), len)) }
    }
    unsafe fn has_dollar(p: *const u32) -> bool {
        unsafe {
            let mut i = 0;
            while *p.add(i) != 0 {
                if *p.add(i) == u32::from(b'$') {
                    return true;
                }
                i += 1;
            }
            false
        }
    }
}

#[cold]
#[inline(never)]
fn tag_zero(wc: u32) -> Option<usize> {
    if (wc >> 7) == (0xe0000 >> 7) { Some(0) } else { None }
}

pub trait Sink {
    const WIDE: bool = false;
    fn put_wide(&mut self, w: &[u32]) -> bool {
        for &c in w {
            let mut b = [0u8; 6];
            let Some(n) = rusty_libc_wchar::mbyte::encode_char(c, &mut b).or_else(|| tag_zero(c)) else {
                errno::set(EILSEQ);
                return false;
            };
            if !self.put(&b[..n]) {
                return false;
            }
        }
        true
    }
    fn put(&mut self, bytes: &[u8]) -> bool;
    fn partial_output_on_error(&self) -> bool {
        true
    }
    fn put_repeat(&mut self, byte: u8, mut n: usize) -> bool {
        let chunk = [byte; 64];
        while n > 0 {
            let k = n.min(64);
            if !self.put(&chunk[..k]) {
                return false;
            }
            n -= k;
        }
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Int,
    Long,
    Double,
    LongDouble,
    Ptr,
}

#[derive(Clone, Copy)]
pub enum Val {
    I(u64),
    D(f64),
    LD([u8; 16]),
    Q(u128),
}

pub trait Args {
    fn get(&mut self, kind: Kind, pos: Option<usize>) -> Val;
    fn raw_va(&mut self) -> *mut core::ffi::c_void {
        core::ptr::null_mut()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Len {
    None,
    HH,
    H,
    L,
    LL,
    BigL,
    J,
    Z,
    T,
    Bad,
}

#[derive(Clone, Copy, Default)]
struct Flags {
    alt: bool,
    group: bool,
    plus: bool,
    space: bool,
    left: bool,
    zero: bool,
    i18n: bool,
}

struct Spec {
    flags: Flags,
    pad0: bool,
    width: usize,
    prec: Option<usize>,
    len: Len,
    conv: u8,
    conv_raw: u32,
    wide_fmt: bool,
}

const fn hex_pairs(upper: bool) -> [u16; 256] {
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = digs[i >> 4] as u16 | ((digs[i & 15] as u16) << 8);
        i += 1;
    }
    t
}
static HEX_LOWER: [u16; 256] = hex_pairs(false);
static HEX_UPPER: [u16; 256] = hex_pairs(true);

fn digits_u64(mut v: u64, base: u64, upper: bool, buf: &mut [u8; 70]) -> usize {
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut i = 70;
    if base == 16 {
        let tab = if upper { &HEX_UPPER } else { &HEX_LOWER };
        let nd = if v == 0 { 1 } else { (64 - v.leading_zeros() as usize).div_ceil(4) };
        let b = v.to_be_bytes();
        if v >> 32 == 0 {
            let w = [tab[b[4] as usize], tab[b[5] as usize], tab[b[6] as usize], tab[b[7] as usize]];
            unsafe { (buf.as_mut_ptr().add(62) as *mut [u16; 4]).write_unaligned(w) };
        } else {
            let w = [tab[b[0] as usize], tab[b[1] as usize], tab[b[2] as usize], tab[b[3] as usize], tab[b[4] as usize], tab[b[5] as usize], tab[b[6] as usize], tab[b[7] as usize]];
            unsafe { (buf.as_mut_ptr().add(54) as *mut [u16; 8]).write_unaligned(w) };
        }
        return 70 - nd;
    }
    if base == 10 {
        const PAIRS: &[u8; 200] = b"0001020304050607080910111213141516171819202122232425262728293031323334353637383940414243444546474849\
5051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899";
        while v >= 100 {
            let r = (v % 100) as usize;
            v /= 100;
            i -= 2;
            buf[i] = PAIRS[2 * r];
            buf[i + 1] = PAIRS[2 * r + 1];
        }
        if v >= 10 {
            i -= 2;
            buf[i] = PAIRS[2 * v as usize];
            buf[i + 1] = PAIRS[2 * v as usize + 1];
        } else {
            i -= 1;
            buf[i] = b'0' + v as u8;
        }
        return i;
    }
    if base.is_power_of_two() {
        let shift = base.trailing_zeros();
        let mask = base - 1;
        loop {
            i -= 1;
            buf[i] = digs[(v & mask) as usize];
            v >>= shift;
            if v == 0 {
                break;
            }
        }
        return i;
    }
    loop {
        i -= 1;
        buf[i] = digs[(v % base) as usize];
        v /= base;
        if v == 0 {
            break;
        }
    }
    i
}

unsafe fn read_int<F: FmtChar>(p: *const F, mut i: usize) -> (usize, usize, bool) {
    let mut v: usize = 0;
    let mut over = false;
    unsafe {
        while F::at(p, i).is_ascii_digit() {
            match v.checked_mul(10).and_then(|x| x.checked_add((F::at(p, i) - b'0') as usize)) {
                Some(x) if x <= i32::MAX as usize => v = x,
                _ => over = true,
            }
            i += 1;
        }
    }
    (v, i, over)
}

unsafe fn try_pos<F: FmtChar>(p: *const F, i: usize) -> Option<(usize, usize)> {
    unsafe {
        if !F::at(p, i).is_ascii_digit() {
            return None;
        }
        let (n, j, _) = read_int(p, i);
        if F::at(p, j) == b'$' && n > 0 { Some((n, j + 1)) } else { None }
    }
}

pub struct PosKinds {
    pub kinds: [Option<Kind>; 128],
    pub max: usize,
}

fn kind_of(conv: u8, len: Len) -> Option<Kind> {
    Some(match conv {
        b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'b' | b'B' => {
            if matches!(len, Len::L | Len::LL | Len::BigL | Len::J | Len::Z | Len::T) { Kind::Long } else { Kind::Int }
        }
        b'c' | b'C' => Kind::Int,
        b's' | b'S' | b'p' | b'n' => Kind::Ptr,
        b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => if len == Len::BigL { Kind::LongDouble } else { Kind::Double },
        _ => return None,
    })
}

pub unsafe fn scan_positional<F: FmtChar>(fmt: *const F) -> Option<PosKinds> {
    unsafe {
        if crate::printf_ext::active() {
            return None;
        }
        let mut pk = PosKinds { kinds: [None; 128], max: 0 };
        let mut any = false;
        let mut seq = 0usize;
        let mut i = 0;
        let note = |pos: usize, k: Kind, pk: &mut PosKinds| {
            if (1..=128).contains(&pos) {
                pk.kinds[pos - 1] = Some(k);
                if pos > pk.max {
                    pk.max = pos;
                }
            }
        };
        while F::at(fmt, i) != 0 {
            if F::at(fmt, i) != b'%' {
                i += 1;
                continue;
            }
            i += 1;
            if F::at(fmt, i) == b'%' {
                i += 1;
                continue;
            }
            let mut pos = 0;
            if let Some((n, j)) = try_pos(fmt, i) {
                pos = n;
                i = j;
                any = true;
            }
            while matches!(F::at(fmt, i), b'-' | b' ' | b'+' | b'#' | b'0' | b'\'' | b'I') {
                i += 1;
            }
            if F::at(fmt, i) == b'*' {
                i += 1;
                let mut explicit = false;
                if let Some((n, j)) = try_pos(fmt, i) {
                    note(n, Kind::Int, &mut pk);
                    i = j;
                    any = true;
                    explicit = true;
                }
                if !explicit {
                    seq += 1;
                    note(seq, Kind::Int, &mut pk);
                }
            } else {
                while F::at(fmt, i).is_ascii_digit() {
                    i += 1;
                }
            }
            if F::at(fmt, i) == b'.' {
                i += 1;
                if F::at(fmt, i) == b'*' {
                    i += 1;
                    let mut explicit = false;
                    if let Some((n, j)) = try_pos(fmt, i) {
                        note(n, Kind::Int, &mut pk);
                        i = j;
                        any = true;
                        explicit = true;
                    }
                    if !explicit {
                        seq += 1;
                        note(seq, Kind::Int, &mut pk);
                    }
                } else {
                    while F::at(fmt, i).is_ascii_digit() {
                        i += 1;
                    }
                }
            }
            let (len, ni) = parse_len(fmt, i);
            i = ni;
            let c = F::at(fmt, i);
            if c == 0 {
                break;
            }
            i += 1;
            if let Some(k) = kind_of(c, len) {
                if pos != 0 {
                    note(pos, k, &mut pk);
                } else {
                    seq += 1;
                    note(seq, k, &mut pk);
                }
            }
        }
        if any { Some(pk) } else { None }
    }
}

unsafe fn parse_len<F: FmtChar>(fmt: *const F, mut i: usize) -> (Len, usize) {
    unsafe {
        let c = F::at(fmt, i);
        let len = match c {
            b'h' => {
                if F::at(fmt, i + 1) == b'h' {
                    i += 1;
                    Len::HH
                } else {
                    Len::H
                }
            }
            b'l' => {
                if F::at(fmt, i + 1) == b'l' {
                    i += 1;
                    Len::LL
                } else {
                    Len::L
                }
            }
            b'L' => Len::BigL,
            b'q' => Len::LL,
            b'j' => Len::J,
            b'z' | b'Z' => Len::Z,
            b't' => Len::T,
            b'w' => {
                let mut j = i + 1;
                let fast = F::at(fmt, j) == b'f';
                if fast {
                    j += 1;
                }
                let mut bits = 0u32;
                let start = j;
                while F::at(fmt, j).is_ascii_digit() && j - start < 3 {
                    bits = bits * 10 + u32::from(F::at(fmt, j) - b'0');
                    j += 1;
                }
                let len = match (fast, bits) {
                    (_, 8) => Len::HH,
                    (false, 16) => Len::H,
                    (false, 32) => Len::None,
                    (false, 64) | (true, 16 | 32 | 64) => Len::L,
                    _ => Len::Bad,
                };
                return (len, j);
            }
            _ => return (Len::None, i),
        };
        (len, i + 1)
    }
}

pub(crate) fn strerror_text(code: i32, buf: &mut [u8; 40]) -> &[u8] {
    if let Some(m) = rusty_libc_core::messages::error_message(code) {
        return m.to_bytes();
    }
    let prefix = b"Unknown error ";
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut n = prefix.len();
    let mut tmp = [0u8; 12];
    let mut v = i64::from(code).unsigned_abs();
    let mut k = 12;
    loop {
        k -= 1;
        tmp[k] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if code < 0 {
        buf[n] = b'-';
        n += 1;
    }
    for &d in &tmp[k..] {
        buf[n] = d;
        n += 1;
    }
    &buf[..n]
}

pub struct Out<'a, S: Sink> {
    sink: &'a mut S,
    total: usize,
    failed: bool,
}

impl<S: Sink> Out<'_, S> {
    pub fn put_w(&mut self, w: &[u32]) {
        if self.failed || w.is_empty() {
            return;
        }
        if !S::WIDE {
            for &c in w {
                let mut b = [0u8; 6];
                let Some(n) = rusty_libc_wchar::mbyte::encode_char(c, &mut b).or_else(|| tag_zero(c)) else {
                    errno::set(EILSEQ);
                    self.failed = true;
                    return;
                };
                self.put(&b[..n]);
            }
            return;
        }
        self.total = self.total.saturating_add(w.len());
        if !self.sink.put_wide(w) {
            self.failed = true;
        }
    }
    pub fn put(&mut self, b: &[u8]) {
        if self.failed || b.is_empty() {
            return;
        }
        self.total = self.total.saturating_add(b.len());
        if !self.sink.put(b) {
            self.failed = true;
        }
    }
    fn rep(&mut self, byte: u8, n: usize) {
        if self.failed || n == 0 {
            return;
        }
        self.total = self.total.saturating_add(n);
        if !self.sink.put_repeat(byte, n) {
            self.failed = true;
        }
    }
}

struct Num<'a> {
    sign: &'a [u8],
    prefix: &'a [u8],
    zeros: usize,
    body: &'a [u8],
    tail: &'a [u8],
    mid: [Piece<'a>; 5],
}

#[derive(Clone, Copy)]
enum Piece<'a> {
    Bytes(&'a [u8]),
    Zeros(usize),
    None,
}

fn piece_len(p: &Piece) -> usize {
    match p {
        Piece::Bytes(b) => b.len(),
        Piece::Zeros(n) => *n,
        Piece::None => 0,
    }
}

#[inline(always)]
pub unsafe fn small_copy(dst: *mut u8, src: *const u8, n: usize) {
    unsafe {
        if (8..=16).contains(&n) {
            let a = (src as *const u64).read_unaligned();
            let b = (src.add(n - 8) as *const u64).read_unaligned();
            (dst as *mut u64).write_unaligned(a);
            (dst.add(n - 8) as *mut u64).write_unaligned(b);
        } else if (4..8).contains(&n) {
            let a = (src as *const u32).read_unaligned();
            let b = (src.add(n - 4) as *const u32).read_unaligned();
            (dst as *mut u32).write_unaligned(a);
            (dst.add(n - 4) as *mut u32).write_unaligned(b);
        } else if n > 16 {
            rusty_libc_mem::memcpy(dst.cast(), src.cast(), n);
        } else {
            for i in 0..n {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

#[inline(always)]
unsafe fn small_fill(dst: *mut u8, byte: u8, n: usize) {
    unsafe {
        if n >= 8 {
            let w = u64::from_ne_bytes([byte; 8]);
            let mut i = 0;
            while i + 8 < n {
                (dst.add(i) as *mut u64).write_unaligned(w);
                i += 8;
            }
            (dst.add(n - 8) as *mut u64).write_unaligned(w);
        } else if n >= 4 {
            let w = u32::from_ne_bytes([byte; 4]);
            (dst as *mut u32).write_unaligned(w);
            (dst.add(n - 4) as *mut u32).write_unaligned(w);
        } else {
            for i in 0..n {
                *dst.add(i) = byte;
            }
        }
    }
}

fn write_num<S: Sink>(o: &mut Out<S>, n: &Num, width: usize, left: bool, zero_pad: bool, rpad: u8) {
    let mut len = n.sign.len() + n.prefix.len() + n.zeros + n.body.len() + n.tail.len();
    for p in &n.mid {
        len += piece_len(p);
    }
    let pad = width.saturating_sub(len);
    if len + pad <= 192 && !o.failed {
        let mut raw = core::mem::MaybeUninit::<[u8; 192]>::uninit();
        let base = raw.as_mut_ptr() as *mut u8;
        let mut k = 0usize;
        unsafe {
            let copy = |src: &[u8], k: &mut usize| {
                small_copy(base.add(*k), src.as_ptr(), src.len());
                *k += src.len();
            };
            let fill = |byte: u8, cnt: usize, k: &mut usize| {
                small_fill(base.add(*k), byte, cnt);
                *k += cnt;
            };
            if !left && !zero_pad {
                fill(b' ', pad, &mut k);
            }
            copy(n.sign, &mut k);
            copy(n.prefix, &mut k);
            if !left && zero_pad {
                fill(b'0', pad, &mut k);
            }
            fill(b'0', n.zeros, &mut k);
            copy(n.body, &mut k);
            for p in &n.mid {
                match p {
                    Piece::Bytes(b) => copy(b, &mut k),
                    Piece::Zeros(z) => fill(b'0', *z, &mut k),
                    Piece::None => {}
                }
            }
            copy(n.tail, &mut k);
            if left && rpad != 0 {
                fill(rpad, pad, &mut k);
            }
            o.put(core::slice::from_raw_parts(base, k));
        }
        return;
    }
    if !left && !zero_pad {
        o.rep(b' ', pad);
    }
    o.put(n.sign);
    o.put(n.prefix);
    if !left && zero_pad {
        o.rep(b'0', pad);
    }
    o.rep(b'0', n.zeros);
    o.put(n.body);
    for p in &n.mid {
        match p {
            Piece::Bytes(b) => o.put(b),
            Piece::Zeros(z) => o.rep(b'0', *z),
            Piece::None => {}
        }
    }
    o.put(n.tail);
    if left && rpad != 0 {
        o.rep(rpad, pad);
    }
}

fn val_i(v: Val) -> u64 {
    match v {
        Val::I(x) => x,
        _ => 0,
    }
}

fn decode_x87(b: [u8; 16]) -> (bool, i32, u64) {
    let mant = u64::from_le_bytes(b[..8].try_into().unwrap());
    let se = u16::from_le_bytes([b[8], b[9]]);
    ((se >> 15) != 0, i32::from(se & 0x7fff), mant)
}

#[inline(always)]
pub unsafe fn format<S: Sink, A: Args, F: FmtChar>(sink: &mut S, fmt: *const F, args: &mut A) -> i32 {
    unsafe {
        if crate::printf_ext::active() {
            return crate::printf_ext::format_ext::<S, A, F>(sink, fmt, args);
        }
        format_builtin(sink, fmt, args)
    }
}

pub unsafe fn format_builtin<S: Sink, A: Args, F: FmtChar>(sink: &mut S, fmt: *const F, args: &mut A) -> i32 {
    unsafe {
        let mut o = Out { sink, total: 0, failed: false };
        let mut i = 0usize;
        let mut run_start = 0usize;
        let mut slow = false;
        loop {
            let rc = F::raw(fmt, i);
            if rc != 0 && rc != u32::from(b'%') {
                i += 1;
                continue;
            }
            let c = if rc == 0 { 0 } else { b'%' };
            if i > run_start {
                F::emit_run(&mut o, fmt, run_start, i - run_start);
            }
            if o.failed {
                return -1;
            }
            if c == 0 {
                break;
            }
            i += 1;
            let mut bj = i;
            let mut bw = 0usize;
            while bj < i + 4 && F::at(fmt, bj).is_ascii_digit() && (bj > i || F::at(fmt, bj) != b'0') {
                bw = bw * 10 + usize::from(F::at(fmt, bj) - b'0');
                bj += 1;
            }
            let bare = F::at(fmt, bj);
            let is_bare = matches!(bare, b's' | b'd' | b'i' | b'u' | b'x' | b'c');
            let mut spec = Spec { flags: Flags::default(), pad0: false, width: if is_bare { bw } else { 0 }, prec: None, len: Len::None, conv: if is_bare { bare } else { 0 }, conv_raw: if is_bare { F::raw(fmt, bj) } else { 0 }, wide_fmt: F::WIDE };
            let mut pos: Option<usize> = None;
            if is_bare {
                i = bj;
            } else {
                let mut positional_seen = false;
                if let Some((n, j)) = try_pos(fmt, i) {
                    pos = Some(n);
                    positional_seen = true;
                    i = j;
                }
                loop {
                    match F::at(fmt, i) {
                        b'-' => spec.flags.left = true,
                        b' ' => spec.flags.space = true,
                        b'+' => spec.flags.plus = true,
                        b'#' => spec.flags.alt = true,
                        b'0' => spec.flags.zero = true,
                        b'\'' => spec.flags.group = true,
                        b'I' => spec.flags.i18n = true,
                        _ => break,
                    }
                    i += 1;
                }
                let explicit_minus = spec.flags.left;
                let mut neg_width_arg = false;
                if F::at(fmt, i) == b'*' {
                    i += 1;
                    let mut wpos = None;
                    if let Some((n, j)) = try_pos(fmt, i) {
                        wpos = Some(n);
                        positional_seen = true;
                        i = j;
                    }
                    let w = val_i(args.get(Kind::Int, wpos)) as u32 as i32;
                    if w < 0 {
                        spec.flags.left = true;
                        neg_width_arg = true;
                        spec.width = (i64::from(w)).unsigned_abs() as usize;
                    } else {
                        spec.width = w as usize;
                    }
                } else if F::at(fmt, i).is_ascii_digit() {
                    let (n, j, over) = read_int(fmt, i);
                    if over {
                        errno::set(EOVERFLOW);
                        return -1;
                    }
                    spec.width = n;
                    i = j;
                }
                if F::at(fmt, i) == b'.' {
                    i += 1;
                    if F::at(fmt, i) == b'*' {
                        i += 1;
                        let mut ppos = None;
                        if let Some((n, j)) = try_pos(fmt, i) {
                            ppos = Some(n);
                            positional_seen = true;
                            i = j;
                        }
                        let p = val_i(args.get(Kind::Int, ppos)) as u32 as i32;
                        spec.prec = if p < 0 { None } else { Some(p as usize) };
                    } else {
                        let (n, j, over) = read_int(fmt, i);
                        if over {
                            errno::set(EOVERFLOW);
                            return -1;
                        }
                        spec.prec = Some(n);
                        i = j;
                    }
                }
                let (len, ni) = parse_len(fmt, i);
                if len == Len::Bad {
                    errno::set(EINVAL);
                    return -1;
                }
                spec.len = len;
                i = ni;
                let conv = F::at(fmt, i);
                spec.conv = conv;
                spec.conv_raw = F::raw(fmt, i);
                if positional_seen {
                    slow = true;
                }
                spec.pad0 = neg_width_arg && spec.flags.zero && !explicit_minus && slow;
                if conv != 0 && spec.len == Len::H && !matches!(conv, b'd' | b'i' | b'u' | b'o' | b'x' | b'X' | b'n' | b'b' | b'B' | b'%') {
                    slow = true;
                }
                if conv == 0 {
                    if slow {
                        unknown(&mut o, &spec);
                        break;
                    }
                    errno::set(EINVAL);
                    return -1;
                }
            }
            i += 1;
            run_start = i;
            if convert(&mut o, &spec, pos, args) {
                slow = true;
            }
            if o.failed {
                return -1;
            }
            if let Some(e) = o_error(&o) {
                errno::set(e);
                return -1;
            }
        }
        if o.failed {
            return -1;
        }
        if o.total > i32::MAX as usize {
            errno::set(EOVERFLOW);
            return -1;
        }
        o.total as i32
    }
}

fn o_error<S: Sink>(o: &Out<S>) -> Option<i32> {
    if o.total > i32::MAX as usize { Some(EOVERFLOW) } else { None }
}

fn unknown<S: Sink>(o: &mut Out<S>, s: &Spec) {
    o.put(b"%");
    let f = &s.flags;
    if f.alt {
        o.put(b"#");
    }
    if f.group {
        o.put(b"'");
    }
    if f.plus {
        o.put(b"+");
    } else if f.space {
        o.put(b" ");
    }
    if f.left {
        o.put(b"-");
    }
    if f.zero && !f.left {
        o.put(b"0");
    }
    if f.i18n {
        o.put(b"I");
    }
    let mut buf = [0u8; 70];
    if s.width != 0 {
        let i = digits_u64(s.width as u64, 10, false, &mut buf);
        o.put(&buf[i..]);
    }
    if let Some(p) = s.prec {
        o.put(b".");
        if p == 0 {
            o.put(b"0");
        } else {
            let i = digits_u64(p as u64, 10, false, &mut buf);
            o.put(&buf[i..]);
        }
    }
    if s.conv != 0 {
        if s.wide_fmt {
            o.put_w(&[s.conv_raw]);
        } else {
            o.put(&[s.conv]);
        }
    }
}

unsafe fn convert<S: Sink, A: Args>(o: &mut Out<S>, s: &Spec, pos: Option<usize>, args: &mut A) -> bool {
    unsafe {
        let f = s.flags;
        match s.conv {
            b'%' => o.put(b"%"),
            b'd' | b'i' => {
                let v = val_i(args.get(kind_of(s.conv, s.len).unwrap(), pos));
                let signed: i64 = match s.len {
                    Len::HH => i64::from(v as i8),
                    Len::H => i64::from(v as i16),
                    Len::None => i64::from(v as i32),
                    _ => v as i64,
                };
                let neg = signed < 0;
                let mag = signed.unsigned_abs();
                let sign: &[u8] = if neg { b"-" } else if f.plus { b"+" } else if f.space { b" " } else { b"" };
                emit_int(o, s, sign, b"", mag, 10, false);
            }
            b'u' | b'o' | b'x' | b'X' | b'b' | b'B' => {
                let v = val_i(args.get(kind_of(s.conv, s.len).unwrap(), pos));
                let mag: u64 = match s.len {
                    Len::HH => u64::from(v as u8),
                    Len::H => u64::from(v as u16),
                    Len::None => u64::from(v as u32),
                    _ => v,
                };
                let (base, upper) = match s.conv {
                    b'u' => (10, false),
                    b'o' => (8, false),
                    b'x' => (16, false),
                    b'X' => (16, true),
                    _ => (2, false),
                };
                let prefix: &[u8] = if f.alt && mag != 0 {
                    match s.conv {
                        b'x' => b"0x",
                        b'X' => b"0X",
                        b'b' => b"0b",
                        b'B' => b"0B",
                        _ => b"",
                    }
                } else {
                    b""
                };
                emit_int(o, s, b"", prefix, mag, base, upper);
            }
            b'c' | b'C' => {
                let v = val_i(args.get(Kind::Int, pos)) as u32;
                let wide_arg = s.conv == b'C' || s.len == Len::L;
                let pad = s.width.saturating_sub(1);
                if S::WIDE {
                    let ch = if wide_arg { v } else if v & 0xff < 0x80 { v & 0xff } else { u32::MAX };
                    if !f.left {
                        o.rep(b' ', pad);
                    }
                    o.put_w(&[ch]);
                    if f.left {
                        o.rep(b' ', pad);
                    }
                } else if wide_arg {
                    let mut b = [0u8; 6];
                    let Some(n) = rusty_libc_wchar::mbyte::encode_char(v, &mut b).or_else(|| tag_zero(v)) else {
                        errno::set(EILSEQ);
                        o.failed = true;
                        return false;
                    };
                    let pad = s.width.saturating_sub(n);
                    if !f.left {
                        o.rep(b' ', pad);
                    }
                    o.put(&b[..n]);
                    if f.left {
                        o.rep(b' ', pad);
                    }
                } else {
                    let b = [(v & 0xff) as u8];
                    if !f.left {
                        o.rep(b' ', pad);
                    }
                    o.put(&b);
                    if f.left {
                        o.rep(b' ', pad);
                    }
                }
            }
            b's' | b'S' => {
                let p = val_i(args.get(Kind::Ptr, pos)) as usize;
                let wide = s.conv == b'S' || s.len == Len::L;
                emit_str(o, s, p, wide);
            }
            b'm' => {
                let mut buf = [0u8; 40];
                let code = errno::get();
                let named: &[u8] = if f.alt { rusty_libc_core::messages::error_name(code).map_or(b"", |n| n.to_bytes()) } else { b"" };
                let text: &[u8] = if f.alt {
                    if named.is_empty() {
                        let mut tmp = [0u8; 70];
                        let st = digits_u64(i64::from(code).unsigned_abs(), 10, false, &mut tmp);
                        let mut n = 0;
                        if code < 0 {
                            buf[0] = b'-';
                            n = 1;
                        }
                        for &d in &tmp[st..] {
                            buf[n] = d;
                            n += 1;
                        }
                        &buf[..n]
                    } else {
                        named
                    }
                } else {
                    strerror_text(code, &mut buf)
                };
                let n = match s.prec {
                    Some(p) => text.len().min(p),
                    None => text.len(),
                };
                let pad = s.width.saturating_sub(n);
                if !f.left {
                    o.rep(b' ', pad);
                }
                o.put(&text[..n]);
                if f.left {
                    o.rep(b' ', pad);
                }
            }
            b'p' => {
                let p = val_i(args.get(Kind::Ptr, pos));
                if p == 0 {
                    let pad = s.width.saturating_sub(5);
                    if !f.left {
                        o.rep(b' ', pad);
                    }
                    o.put(b"(nil)");
                    if f.left {
                        o.rep(b' ', pad);
                    }
                } else {
                    let sign: &[u8] = if f.plus { b"+" } else if f.space { b" " } else { b"" };
                    emit_int(o, s, sign, b"0x", p, 16, false);
                }
            }
            b'n' => {
                let p = val_i(args.get(Kind::Ptr, pos)) as usize;
                let total = o.total;
                if p != 0 {
                    match s.len {
                        Len::HH => *(p as *mut i8) = total as i8,
                        Len::H => *(p as *mut i16) = total as i16,
                        Len::None => *(p as *mut i32) = total as i32,
                        _ => *(p as *mut i64) = total as i64,
                    }
                }
            }
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => {
                emit_float(o, s, args.get(kind_of(s.conv, s.len).unwrap(), pos));
            }
            _ => {
                unknown(o, s);
                return true;
            }
        }
        false
    }
}

fn out_digits(on: bool) -> Option<&'static rusty_libc_core::locale::CatData> {
    if !on {
        return None;
    }
    let c = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE);
    if c.is_null() { None } else { Some(unsafe { &*c }) }
}

fn put_ch<S: Sink>(o: &mut Out<S>, tr: Option<&rusty_libc_core::locale::CatData>, c: u8) {
    use rusty_libc_core::locale::idx;
    match tr {
        Some(d) if c.is_ascii_digit() => {
            let k = (c - b'0') as usize;
            if S::WIDE {
                o.put_w(&[d.word(idx::CTYPE_OUTDIGIT0_WC + k)]);
            } else {
                o.put(d.bytes(idx::CTYPE_OUTDIGIT0_MB + k));
            }
        }
        _ => o.put(&[c]),
    }
}

fn put_txt<S: Sink>(o: &mut Out<S>, tr: Option<&rusty_libc_core::locale::CatData>, t: &[u8]) {
    if tr.is_none() {
        o.put(t);
    } else {
        for &c in t {
            put_ch(o, tr, c);
        }
    }
}

fn put_zeros<S: Sink>(o: &mut Out<S>, tr: Option<&rusty_libc_core::locale::CatData>, n: usize) {
    if tr.is_none() {
        o.rep(b'0', n);
    } else {
        for _ in 0..n {
            put_ch(o, tr, b'0');
        }
    }
}

fn put_sep<S: Sink>(o: &mut Out<S>, nu: &rusty_libc_core::locale::Numeric) {
    if S::WIDE {
        if nu.thousands_wc != 0 {
            o.put_w(&[nu.thousands_wc]);
        }
    } else {
        o.put(nu.thousands_sep);
    }
}

fn emit_int_loc<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], prefix: &[u8], mag: u64, base: u64, upper: bool) {
    let mut buf = [0u8; 70];
    let start = digits_u64(mag, base, upper, &mut buf);
    let mut digits = &buf[start..];
    if mag == 0 && s.prec == Some(0) {
        digits = if s.conv == b'o' && s.flags.alt { b"0" } else { b"" };
    }
    let f = s.flags;
    let nu = rusty_libc_core::locale::numeric();
    let use_out = f.i18n && base == 10;
    let tr = out_digits(use_out);
    let prec = s.prec.unwrap_or(1) as isize;
    let nd = digits.len();
    let mut it = if f.group { nu.group_iter(nd) } else { nu.group_iter(0) };
    let mut number_length = nd as isize;
    if let (Some(d), false) = (tr, S::WIDE) {
        number_length = digits.iter().map(|&c| d.bytes(rusty_libc_core::locale::idx::CTYPE_OUTDIGIT0_MB + (c - b'0') as usize).len() as isize).sum();
    }
    if f.group {
        let seplen = if S::WIDE { isize::from(nu.thousands_wc != 0) } else { nu.thousands_sep.len() as isize };
        number_length += it.separators as isize * seplen;
    }
    let octal_marker = prec <= number_length && mag != 0 && f.alt && base == 8;
    let prec_inc = (prec - nd as isize).max(0);
    let pad_zero = f.zero && s.prec.is_none() && !f.left;
    let mut width = s.width as isize;
    let emit_digits = |o: &mut Out<S>, it: &mut rusty_libc_core::locale::GroupIter| {
        for &c in digits {
            if f.group && it.next_digit() {
                put_sep(o, &nu);
            }
            put_ch(o, tr, c);
        }
    };
    if !f.left {
        width -= number_length + prec_inc;
        width -= prefix.len() as isize + isize::from(octal_marker) + sign.len() as isize;
        if !pad_zero {
            o.rep(b' ', width.max(0) as usize);
            width = 0;
        }
        o.put(sign);
        o.put(prefix);
        width += prec_inc;
        o.rep(b'0', width.max(0) as usize);
        if octal_marker {
            o.put(b"0");
        }
        emit_digits(o, &mut it);
    } else {
        o.put(sign);
        o.put(prefix);
        width -= sign.len() as isize + prefix.len() as isize + isize::from(octal_marker);
        width -= number_length + prec_inc;
        o.rep(b'0', prec_inc as usize);
        if octal_marker {
            o.put(b"0");
        }
        emit_digits(o, &mut it);
        o.rep(b' ', width.max(0) as usize);
    }
}

fn float_rpad(s: &Spec) -> u8 {
    if !s.pad0 {
        b' '
    } else if matches!(s.conv, b'a' | b'A') {
        0
    } else {
        b'0'
    }
}

fn write_pieces_loc<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], p: &float::Pieces, zero_pad: bool) {
    let nu = rusty_libc_core::locale::numeric();
    let hex = s.conv | 0x20 == b'a';
    let sep_present = if S::WIDE { nu.thousands_wc != 0 } else { !nu.thousands_sep.is_empty() };
    let intdig = p.int.len() + p.int_zeros;
    let grouping = s.flags.group && !hex && sep_present;
    let mut it = if grouping { nu.group_iter(intdig) } else { nu.group_iter(0) };
    let tr = out_digits(s.flags.i18n && !hex);
    let vanish = s.flags.i18n && !hex && !S::WIDE && match tr {
        None => true,
        Some(d) => d.flags & rusty_libc_core::locale::F_BUILTIN_C != 0,
    };
    let chars = p.prefix.len() + intdig + usize::from(p.point) + p.frac_lead_zeros + p.frac.len() + p.frac_zeros + p.tail_len + it.separators as usize;
    let width = (s.width as isize - sign.len() as isize - chars as isize).max(0) as usize;
    let left = s.flags.left;
    if !left && !zero_pad {
        o.rep(b' ', width);
    }
    o.put(sign);
    o.put(p.prefix);
    if !left && zero_pad {
        o.rep(b'0', width);
    }
    for i in 0..intdig {
        if grouping && it.next_digit() {
            put_sep(o, &nu);
        }
        if !vanish {
            put_ch(o, tr, if i < p.int.len() { p.int[i] } else { b'0' });
        }
    }
    if p.point {
        if S::WIDE {
            o.put_w(&[nu.decimal_wc]);
        } else {
            o.put(nu.decimal_point);
        }
    }
    if vanish {
        for &c in &p.tail[..p.tail_len] {
            if !c.is_ascii_digit() {
                o.put(&[c]);
            }
        }
    } else {
        put_zeros(o, tr, p.frac_lead_zeros);
        put_txt(o, tr, p.frac);
        put_zeros(o, tr, p.frac_zeros);
        put_txt(o, tr, &p.tail[..p.tail_len]);
    }
    let rpad = float_rpad(s);
    if left && rpad != 0 {
        o.rep(rpad, width);
    }
}

#[inline]
fn float_needs_locale(s: &Spec) -> bool {
    if s.flags.group || s.flags.i18n {
        return true;
    }
    let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC);
    !rusty_libc_core::locale::numeric_dot(d)
}

fn emit_int<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], prefix: &[u8], mag: u64, base: u64, upper: bool) {
    if s.flags.group || (s.flags.i18n && base == 10) {
        return emit_int_loc(o, s, sign, prefix, mag, base, upper);
    }
    let mut buf = [0u8; 70];
    let start = digits_u64(mag, base, upper, &mut buf);
    if s.width == 0 && s.prec.is_none() && prefix.is_empty() && sign.len() <= 1 && !(s.conv == b'o' && s.flags.alt) {
        if let Some(&sg) = sign.first() {
            buf[start - 1] = sg;
            o.put(&buf[start - 1..]);
        } else {
            o.put(&buf[start..]);
        }
        return;
    }
    let mut digits = &buf[start..];
    if mag == 0 && s.prec == Some(0) {
        digits = &[];
    }
    let mut zeros = s.prec.map_or(0, |p| p.saturating_sub(digits.len()));
    if s.conv == b'o' && s.flags.alt && zeros == 0 && (digits.is_empty() || digits[0] != b'0') {
        zeros = 1;
    }
    let zero_pad = s.flags.zero && s.prec.is_none() && !s.flags.left;
    let total = sign.len() + prefix.len() + zeros + digits.len();
    let pad = s.width.saturating_sub(total);
    if !s.flags.left && sign.len() <= 1 && prefix.len() <= 2 && total + pad <= 192 && !o.failed {
        let mut raw = core::mem::MaybeUninit::<[u8; 192]>::uninit();
        let base = raw.as_mut_ptr() as *mut u8;
        unsafe {
            let mut k = 0usize;
            if !zero_pad {
                small_fill(base, b' ', pad);
                k += pad;
            }
            if let Some(&sg) = sign.first() {
                *base.add(k) = sg;
                k += 1;
            }
            for &c in prefix {
                *base.add(k) = c;
                k += 1;
            }
            if zero_pad {
                small_fill(base.add(k), b'0', pad);
                k += pad;
            }
            small_fill(base.add(k), b'0', zeros);
            k += zeros;
            small_copy(base.add(k), digits.as_ptr(), digits.len());
            k += digits.len();
            o.put(core::slice::from_raw_parts(base, k));
        }
        return;
    }
    let n = Num { sign, prefix, zeros, body: digits, tail: b"", mid: [Piece::None; 5] };
    write_num(o, &n, s.width, s.flags.left, zero_pad, b' ');
}

struct WBuf {
    inline: core::mem::MaybeUninit<[u32; 128]>,
    heap: *mut u32,
    cap: usize,
    len: usize,
    oom: bool,
}

impl WBuf {
    fn new() -> WBuf {
        WBuf { inline: core::mem::MaybeUninit::uninit(), heap: core::ptr::null_mut(), cap: 0, len: 0, oom: false }
    }
    unsafe fn push(&mut self, c: u32) {
        unsafe {
            if self.heap.is_null() {
                if self.len < 128 {
                    (self.inline.as_mut_ptr() as *mut u32).add(self.len).write(c);
                    self.len += 1;
                    return;
                }
                let nc = 512;
                let h = rusty_libc_malloc::malloc(nc * 4) as *mut u32;
                if h.is_null() {
                    self.oom = true;
                    return;
                }
                core::ptr::copy_nonoverlapping(self.inline.as_ptr() as *const u32, h, self.len);
                self.heap = h;
                self.cap = nc;
            } else if self.len == self.cap {
                let nc = self.cap * 2;
                let h = rusty_libc_malloc::realloc(self.heap.cast(), nc * 4) as *mut u32;
                if h.is_null() {
                    self.oom = true;
                    return;
                }
                self.heap = h;
                self.cap = nc;
            }
            *self.heap.add(self.len) = c;
            self.len += 1;
        }
    }
    unsafe fn as_slice(&self) -> &[u32] {
        unsafe { if self.heap.is_null() { core::slice::from_raw_parts(self.inline.as_ptr() as *const u32, self.len) } else { core::slice::from_raw_parts(self.heap, self.len) } }
    }
    unsafe fn release(&mut self) {
        unsafe {
            if !self.heap.is_null() {
                rusty_libc_malloc::free(self.heap.cast());
                self.heap = core::ptr::null_mut();
            }
        }
    }
}

unsafe fn emit_str<S: Sink>(o: &mut Out<S>, s: &Spec, p: usize, wide: bool) {
    unsafe {
        let f = s.flags;
        if p == 0 {
            let text: &[u8] = if s.prec.is_none_or(|p| p >= 6) { b"(null)" } else { b"" };
            let pad = s.width.saturating_sub(text.len());
            if !f.left {
                o.rep(b' ', pad);
            }
            o.put(text);
            if f.left {
                o.rep(b' ', pad);
            }
            return;
        }
        if wide {
            let w = p as *const u32;
            if S::WIDE {
                let n = match s.prec {
                    None => rusty_libc_wchar::wstring::wcslen(w as *const rusty_libc_wchar::wchar_t),
                    Some(limit) => rusty_libc_wchar::wstring::wcsnlen(w as *const rusty_libc_wchar::wchar_t, limit),
                };
                let pad = s.width.saturating_sub(n);
                if !f.left {
                    o.rep(b' ', pad);
                }
                o.put_w(if n == 0 { &[] } else { core::slice::from_raw_parts(w, n) });
                if f.left {
                    o.rep(b' ', pad);
                }
                return;
            }
            let limit = s.prec.unwrap_or(usize::MAX);
            let mut bytes = 0usize;
            let mut k = 0usize;
            while *w.add(k) != 0 && bytes < limit {
                let mut b = [0u8; 6];
                let Some(n) = rusty_libc_wchar::mbyte::encode_char(*w.add(k), &mut b).or_else(|| tag_zero(*w.add(k))) else {
                    errno::set(EILSEQ);
                    o.failed = true;
                    return;
                };
                if bytes + n > limit {
                    break;
                }
                bytes += n;
                k += 1;
            }
            let pad = s.width.saturating_sub(bytes);
            if !f.left {
                o.rep(b' ', pad);
            }
            o.put_w(core::slice::from_raw_parts(w, k));
            if f.left {
                o.rep(b' ', pad);
            }
            return;
        }
        if S::WIDE {
            let cs = rusty_libc_wchar::charset();
            let max_bytes = match s.prec {
                None => rusty_libc_mem::strlen(p as *const core::ffi::c_char),
                Some(limit) => rusty_libc_mem::strnlen(p as *const core::ffi::c_char, limit.saturating_mul(6)),
            };
            let bytes = core::slice::from_raw_parts(p as *const u8, max_bytes);
            let limit = s.prec.unwrap_or(usize::MAX);
            let take = bytes.len().min(limit);
            if bytes[..take].iter().all(|&b| b < 0x80) {
                let pad = s.width.saturating_sub(take);
                if !f.left {
                    o.rep(b' ', pad);
                }
                o.put(&bytes[..take]);
                if f.left {
                    o.rep(b' ', pad);
                }
                return;
            }
            let mut wb = WBuf::new();
            let mut pos = 0usize;
            while pos < bytes.len() && wb.len < limit {
                let b0 = bytes[pos];
                if b0 < 0x80 {
                    wb.push(u32::from(b0));
                    pos += 1;
                    continue;
                }
                match rusty_libc_wchar::mbyte::decode_cs(cs, &bytes[pos..]) {
                    rusty_libc_wchar::mbyte::Decoded::Char(c, n) => {
                        wb.push(c);
                        pos += n;
                    }
                    _ => {
                        if s.width > 0 && !f.left && s.prec.is_none() {
                            o.rep(b' ', s.width + 1);
                        }
                        if !o.failed {
                            errno::set(EILSEQ);
                        }
                        o.failed = true;
                        wb.release();
                        return;
                    }
                }
            }
            if wb.oom {
                errno::set(12);
                o.failed = true;
                wb.release();
                return;
            }
            let pad = s.width.saturating_sub(wb.len);
            if !f.left {
                o.rep(b' ', pad);
            }
            o.put_w(wb.as_slice());
            if f.left {
                o.rep(b' ', pad);
            }
            wb.release();
            return;
        }
        let b = p as *const u8;
        let n = match s.prec {
            None => rusty_libc_mem::strlen(b.cast()),
            Some(limit) => rusty_libc_mem::strnlen(b.cast(), limit),
        };
        let pad = s.width.saturating_sub(n);
        if !f.left {
            o.rep(b' ', pad);
        }
        o.put(core::slice::from_raw_parts(b, n));
        if f.left {
            o.rep(b' ', pad);
        }
    }
}

fn emit_float<S: Sink>(o: &mut Out<S>, s: &Spec, v: Val) {
    let f = s.flags;
    let upper = s.conv.is_ascii_uppercase();
    let (neg, class, mant, exp2, bits64) = match v {
        Val::D(x) => {
            let b = x.to_bits();
            let e = ((b >> 52) & 0x7ff) as i32;
            let frac = b & ((1u64 << 52) - 1);
            let neg = b >> 63 != 0;
            if e == 0x7ff {
                (neg, if frac == 0 { 1 } else { 2 }, 0u128, 0i32, b)
            } else if e == 0 {
                (neg, 0, u128::from(frac), -1074, b)
            } else {
                (neg, 0, u128::from(frac | (1u64 << 52)), e - 1075, b)
            }
        }
        Val::LD(raw) => {
            let (neg, e, m) = decode_x87(raw);
            if e != 0 && m >> 63 == 0 {
                (neg, 2, 0, 0, 0)
            } else if e == 0x7fff {
                (neg, if m << 1 == 0 { 1 } else { 2 }, 0, 0, 0)
            } else if e == 0 {
                (neg, 0, u128::from(m), -16445, 0)
            } else {
                (neg, 0, u128::from(m), e - 16383 - 63, 0)
            }
        }
        Val::Q(b) => {
            let neg = b >> 127 != 0;
            let e = ((b >> 112) & 0x7fff) as i32;
            let frac = b & ((1u128 << 112) - 1);
            if e == 0x7fff {
                (neg, if frac == 0 { 1 } else { 2 }, 0, 0, 0)
            } else if e == 0 {
                (neg, 0, frac, -16494, 0)
            } else {
                (neg, 0, frac | (1u128 << 112), e - 16383 - 112, 0)
            }
        }
        Val::I(_) => (false, 0, 0, 0, 0),
    };
    let sign: &[u8] = if neg { b"-" } else if f.plus { b"+" } else if f.space { b" " } else { b"" };
    if class != 0 {
        let text: &[u8] = match (class, upper) {
            (1, false) => b"inf",
            (1, true) => b"INF",
            (_, false) => b"nan",
            (_, true) => b"NAN",
        };
        let n = Num { sign, prefix: b"", zeros: 0, body: text, tail: b"", mid: [Piece::None; 5] };
        write_num(o, &n, s.width, f.left, false, b' ');
        return;
    }
    let is_ld = matches!(v, Val::LD(_));
    let is_q = matches!(v, Val::Q(_));
    let conv_l = s.conv.to_ascii_lowercase();
    let zero_pad = f.zero && !f.left;
    let rm = float::rounding_class(neg);
    if conv_l == b'a' {
        let mut hex = [0u8; 20];
        if let Val::Q(b) = v {
            let mut small = [0u8; 28];
            let p = float::layout_hex128(&mut small, b & !(1u128 << 127), s.prec, f.alt, upper, rm);
            write_pieces(o, s, sign, &p, zero_pad);
        } else if is_ld {
            emit_hex_ld(o, s, sign, mant as u64, exp2, upper, zero_pad, rm);
        } else {
            let mut small = [0u8; 16];
            let p = float::layout_hex(&mut small, bits64 & 0x7fff_ffff_ffff_ffff, s.prec, f.alt, upper, rm);
            let _ = &mut hex;
            write_pieces(o, s, sign, &p, zero_pad);
        }
        return;
    }
    if is_q {
        let mut d = [0u8; 21000];
        let (len, dp) = float::exact_digits::<530>(mant, exp2, &mut d);
        let p = float::layout(&mut d, len, dp, s.conv, s.prec, f.alt, upper, rm);
        write_pieces(o, s, sign, &p, zero_pad);
    } else if is_ld {
        let prec = match conv_l {
            b'g' => s.prec.unwrap_or(6).max(1),
            _ => s.prec.unwrap_or(6),
        };
        let mut small = [0u8; 48];
        let fast = if conv_l == b'g' && f.alt { None } else { float::fast_digits(mant as u64, exp2, conv_l, prec, &mut small, rm) };
        if let Some((len, dp)) = fast {
            let p = float::layout(&mut small, len, dp, s.conv, s.prec, f.alt, upper, rm);
            write_pieces(o, s, sign, &p, zero_pad);
            return;
        }
        let mut d = [0u8; 21000];
        let (len, dp) = float::exact_digits::<530>(mant, exp2, &mut d);
        let p = float::layout(&mut d, len, dp, s.conv, s.prec, f.alt, upper, rm);
        write_pieces(o, s, sign, &p, zero_pad);
    } else {
        let prec = match conv_l {
            b'g' => s.prec.unwrap_or(6).max(1),
            _ => s.prec.unwrap_or(6),
        };
        let mut small = [0u8; 48];
        let fast = if conv_l == b'g' && f.alt { None } else { float::fast_digits(mant as u64, exp2, conv_l, prec, &mut small, rm) };
        if let Some((len, dp)) = fast {
            let p = float::layout(&mut small, len, dp, s.conv, s.prec, f.alt, upper, rm);
            write_pieces(o, s, sign, &p, zero_pad);
            return;
        }
        let mut d = [0u8; 1500];
        let (len, dp) = float::exact_digits::<40>(mant, exp2, &mut d);
        let p = float::layout(&mut d, len, dp, s.conv, s.prec, f.alt, upper, rm);
        write_pieces(o, s, sign, &p, zero_pad);
    }
}

fn write_pieces<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], p: &float::Pieces, zero_pad: bool) {
    if float_needs_locale(s) {
        return write_pieces_loc(o, s, sign, p, zero_pad);
    }
    let point: &[u8] = if p.point { b"." } else { b"" };
    let n = Num {
        sign,
        prefix: p.prefix,
        zeros: 0,
        body: p.int,
        tail: &p.tail[..p.tail_len],
        mid: [
            Piece::Zeros(p.int_zeros),
            Piece::Bytes(point),
            Piece::Zeros(p.frac_lead_zeros),
            Piece::Bytes(p.frac),
            Piece::Zeros(p.frac_zeros),
        ],
    };
    write_num(o, &n, s.width, s.flags.left, zero_pad, float_rpad(s));
}

#[allow(clippy::collapsible_if)]
#[allow(clippy::too_many_arguments)]
fn emit_hex_ld<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], mant: u64, exp2: i32, upper: bool, zero_pad: bool, rm: u8) {
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut exp = if mant == 0 { 0 } else { exp2 + 60 };
    let mut nib = [0u8; 16];
    for (i, n) in nib.iter_mut().enumerate() {
        *n = ((mant >> (60 - 4 * i)) & 0xf) as u8;
    }
    let mut lead = nib[0];
    let mut frac_n = 15usize;
    if let Some(p) = s.prec {
        if p < 15 {
            let first = nib[1 + p];
            let rest = nib[2 + p..].iter().any(|&x| x != 0);
            let prev = if p == 0 { lead } else { nib[p] };
            let up = match rm {
                1 => first != 0 || rest,
                2 => false,
                _ => first > 8 || (first == 8 && (rest || prev % 2 == 1)),
            };
            frac_n = p;
            if up {
                let mut i = p;
                loop {
                    if i == 0 {
                        lead += 1;
                        if lead == 16 {
                            lead = 1;
                            exp += 4;
                        }
                        break;
                    }
                    if nib[i] == 15 {
                        nib[i] = 0;
                        i -= 1;
                    } else {
                        nib[i] += 1;
                        break;
                    }
                }
            }
        }
    }
    let mut digits = [0u8; 15];
    for i in 0..frac_n.min(15) {
        digits[i] = digs[nib[1 + i] as usize];
    }
    let mut shown = frac_n.min(15);
    let want = match s.prec {
        Some(p) => p,
        None => {
            while shown > 0 && nib[shown] == 0 {
                shown -= 1;
            }
            shown
        }
    };
    let lead_c = [digs[lead as usize]];
    let (t, tl) = {
        let mut t = [0u8; 8];
        t[0] = if upper { b'P' } else { b'p' };
        t[1] = if exp < 0 { b'-' } else { b'+' };
        let mut v = exp.unsigned_abs();
        let mut tmp = [0u8; 6];
        let mut k = 6;
        loop {
            k -= 1;
            tmp[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let mut n = 2;
        for &d in &tmp[k..] {
            t[n] = d;
            n += 1;
        }
        (t, n)
    };
    let p = float::Pieces {
        prefix: if upper { b"0X" } else { b"0x" },
        int: &lead_c,
        int_zeros: 0,
        point: want > 0 || s.flags.alt,
        frac_lead_zeros: 0,
        frac: &digits[..shown],
        frac_zeros: want.saturating_sub(shown),
        tail: t,
        tail_len: tl,
    };
    write_pieces(o, s, sign, &p, zero_pad);
}
