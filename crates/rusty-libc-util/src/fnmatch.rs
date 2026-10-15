#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::cmem::CVec;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicI32, Ordering};
use rusty_libc_locale::coll::{Collation, NO_SEQ};

pub const FNM_PATHNAME: c_int = 1;
pub const FNM_FILE_NAME: c_int = 1;
pub const FNM_NOESCAPE: c_int = 2;
pub const FNM_PERIOD: c_int = 4;
pub const FNM_LEADING_DIR: c_int = 8;
pub const FNM_CASEFOLD: c_int = 16;
pub const FNM_EXTMATCH: c_int = 32;
pub const FNM_NOMATCH: c_int = 1;

const CHAR_CLASS_MAX_LENGTH: usize = 256;

static POSIXLY_CORRECT: AtomicI32 = AtomicI32::new(0);

fn posixly() -> i32 {
    let v = POSIXLY_CORRECT.load(Ordering::Relaxed);
    if v != 0 {
        return v;
    }
    let v = if crate::cmem::getenv(b"POSIXLY_CORRECT").is_none() { -1 } else { 1 };
    POSIXLY_CORRECT.store(v, Ordering::Relaxed);
    v
}

trait Ch: Copy + PartialEq + 'static {
    const WIDE: bool;
    fn v(self) -> u32;
    fn of(v: u32) -> Self;
    fn wide(s: &[Self]) -> Option<&[u32]>;
    fn bytes(s: &[Self]) -> Option<&[u8]>;
}

impl Ch for u8 {
    const WIDE: bool = false;
    #[inline(always)]
    fn v(self) -> u32 {
        self as u32
    }
    #[inline(always)]
    fn of(v: u32) -> u8 {
        v as u8
    }
    fn wide(_: &[u8]) -> Option<&[u32]> {
        None
    }
    fn bytes(s: &[u8]) -> Option<&[u8]> {
        Some(s)
    }
}

impl Ch for u32 {
    const WIDE: bool = true;
    #[inline(always)]
    fn v(self) -> u32 {
        self
    }
    #[inline(always)]
    fn of(v: u32) -> u32 {
        v
    }
    fn wide(s: &[u32]) -> Option<&[u32]> {
        Some(s)
    }
    fn bytes(_: &[u32]) -> Option<&[u8]> {
        None
    }
}

#[inline(always)]
fn k<T: Ch>(b: u8) -> T {
    T::of(b as u32)
}

#[inline(always)]
fn at<T: Ch>(s: &[T], i: usize) -> T {
    match s.get(i) {
        Some(&c) => c,
        None => k(0),
    }
}

const QM: u32 = b'?' as u32;
const STAR: u32 = b'*' as u32;
const BSL: u32 = b'\\' as u32;
const LBR: u32 = b'[' as u32;
const PLUS: u32 = b'+' as u32;
const AT: u32 = b'@' as u32;
const BANG: u32 = b'!' as u32;
const SLASH: u32 = b'/' as u32;

static SPECIAL: [bool; 128] = {
    let mut t = [false; 128];
    let s = b"?*[\\+@!";
    let mut i = 0;
    while i < s.len() {
        t[s[i] as usize] = true;
        i += 1;
    }
    t
};

static STOP: [bool; 128] = {
    let mut t = SPECIAL;
    t[0] = true;
    t
};

#[inline]
fn fold<T: Ch>(c: T, flags: c_int) -> T {
    if flags & FNM_CASEFOLD == 0 {
        c
    } else if T::WIDE {
        T::of(rusty_libc_wchar::wctype::to_lower(c.v()))
    } else {
        T::of(rusty_libc_ctype::to_lower(c.v() as i32) as u32)
    }
}

fn no_leading_period(flags: c_int) -> bool {
    flags & (FNM_FILE_NAME | FNM_PERIOD) == (FNM_FILE_NAME | FNM_PERIOD)
}

struct Ends {
    pattern: Option<usize>,
    string: usize,
    no_leading_period: bool,
}

fn class_test<T: Ch>(name: &[u8], c: T) -> Option<bool> {
    if T::WIDE {
        let desc = rusty_libc_wchar::wctype::class_by_name(name);
        if desc == 0 {
            return None;
        }
        return Some(rusty_libc_wchar::wctype::in_class(c.v(), desc));
    }
    let c = c.v() as i32;
    Some(match name {
        b"alnum" => rusty_libc_ctype::is_alnum(c),
        b"alpha" => rusty_libc_ctype::is_alpha(c),
        b"blank" => rusty_libc_ctype::is_blank(c),
        b"cntrl" => rusty_libc_ctype::is_cntrl(c),
        b"digit" => rusty_libc_ctype::is_digit(c),
        b"graph" => rusty_libc_ctype::is_graph(c),
        b"lower" => rusty_libc_ctype::is_lower(c),
        b"print" => rusty_libc_ctype::is_print(c),
        b"punct" => rusty_libc_ctype::is_punct(c),
        b"space" => rusty_libc_ctype::is_space(c),
        b"upper" => rusty_libc_ctype::is_upper(c),
        b"xdigit" => rusty_libc_ctype::is_xdigit(c),
        _ => return None,
    })
}

#[allow(clippy::almost_complete_range)]
#[inline(always)]
fn class_name(body: &[u8]) -> Option<(usize, u64)> {
    let mut key = 0u64;
    let mut i = 0;
    loop {
        let x = at(body, i);
        if x == b':' && at(body, i + 1) == b']' {
            return Some((i, key));
        }
        if !(b'a'..b'z').contains(&x) || i == 7 {
            return None;
        }
        key |= u64::from(x) << (8 * i);
        i += 1;
    }
}

const fn name_key(name: &[u8]) -> u64 {
    let mut k = 0u64;
    let mut i = 0;
    while i < name.len() {
        k |= (name[i] as u64) << (8 * i);
        i += 1;
    }
    k
}

#[inline(always)]
fn class_test_key(key: u64, c: u8) -> Option<bool> {
    const ALNUM: u64 = name_key(b"alnum");
    const ALPHA: u64 = name_key(b"alpha");
    const BLANK: u64 = name_key(b"blank");
    const CNTRL: u64 = name_key(b"cntrl");
    const DIGIT: u64 = name_key(b"digit");
    const GRAPH: u64 = name_key(b"graph");
    const LOWER: u64 = name_key(b"lower");
    const PRINT: u64 = name_key(b"print");
    const PUNCT: u64 = name_key(b"punct");
    const SPACE: u64 = name_key(b"space");
    const UPPER: u64 = name_key(b"upper");
    const XDIGIT: u64 = name_key(b"xdigit");
    let c = i32::from(c);
    Some(match key {
        ALNUM => rusty_libc_ctype::is_alnum(c),
        ALPHA => rusty_libc_ctype::is_alpha(c),
        BLANK => rusty_libc_ctype::is_blank(c),
        CNTRL => rusty_libc_ctype::is_cntrl(c),
        DIGIT => rusty_libc_ctype::is_digit(c),
        GRAPH => rusty_libc_ctype::is_graph(c),
        LOWER => rusty_libc_ctype::is_lower(c),
        PRINT => rusty_libc_ctype::is_print(c),
        PUNCT => rusty_libc_ctype::is_punct(c),
        SPACE => rusty_libc_ctype::is_space(c),
        UPPER => rusty_libc_ctype::is_upper(c),
        XDIGIT => rusty_libc_ctype::is_xdigit(c),
        _ => return None,
    })
}

fn seq_of<T: Ch>(coll: &Collation, c: T) -> u32 {
    if T::WIDE {
        if coll.nrules() == 0 { if c.v() < 256 { c.v() } else { NO_SEQ } } else { coll.seq_wc(c.v()) }
    } else {
        coll.seq_mb(c.v() as u8)
    }
}

struct Loc {
    coll: Option<Collation>,
}

impl Loc {
    fn get(&mut self) -> &Collation {
        self.coll.get_or_insert_with(Collation::current)
    }
    fn nrules(&mut self) -> u32 {
        self.get().nrules()
    }
}

enum Bracket {
    Matched,
    NotMatched,
    Literal,
    Fail,
}

fn primary<T: Ch>(s: &[T]) -> Option<(u8, &'static [u8], &'static [u32])> {
    debug_assert!(s.last().is_some_and(|c| c.v() == 0));
    if let Some(w) = T::wide(s) {
        let (rule, wt, _) = unsafe { rusty_libc_locale::primary_wc(w.as_ptr()) }?;
        Some((rule, &[], wt))
    } else {
        let b = T::bytes(s)?;
        let (rule, wt, _) = unsafe { rusty_libc_locale::primary_mb(b.as_ptr()) }?;
        Some((rule, wt, &[]))
    }
}

fn equiv_matches<T: Ch>(s: T, n: &[T]) -> bool {
    let pat = [s, k(0)];
    let Some(a) = primary(&pat) else { return false };
    let Some(b) = primary(n) else { return false };
    a == b
}

fn read_symbol<T: Ch>(pat: &[T], p: &mut usize) -> Option<(usize, usize)> {
    let startp = *p;
    let mut c1 = 0usize;
    loop {
        *p += 1;
        let c = at(pat, *p);
        if c.v() == b'.' as u32 && at(pat, *p + 1).v() == b']' as u32 {
            *p += 2;
            break;
        }
        if c.v() == 0 {
            return None;
        }
        c1 += 1;
    }
    Some((startp + 1, c1))
}

fn find_symbol<T: Ch>(coll: &Collation, name: &[T]) -> Option<(u32, usize)> {
    if let Some(w) = T::wide(name) {
        coll.symbol_by_wide(w).map(|(seq, e)| (seq, e.len()))
    } else {
        coll.symbol_by_bytes(T::bytes(name)?).map(|(seq, e)| (seq, e.len()))
    }
}

#[inline]
fn as_cold<T: Ch>(seq: u32) -> u32 {
    if T::WIDE { seq } else { seq as u8 as i8 as i32 as u32 }
}

#[inline]
fn as_cend<T: Ch>(seq: u32) -> u32 {
    if T::WIDE { seq } else { seq as u8 as u32 }
}

#[inline]
fn byte_order_collation() -> bool {
    rusty_libc_core::locale::current(rusty_libc_core::locale::LC_COLLATE).is_none_or(|d| d.flags() & rusty_libc_core::locale::F_BUILTIN_C != 0)
}

#[allow(clippy::almost_complete_range)]
#[inline]
fn bracket_fast(pat: &[u8], p: &mut usize, fnc: u8, nv: u8, flags: c_int) -> Option<Bracket> {
    let noescape = flags & FNM_NOESCAPE != 0;
    let mut q = *p;
    let mut first = true;
    loop {
        let c = at(pat, q);
        if c == 0 || (c == b'\\' && !noescape) {
            return None;
        }
        if c == b']' && !first {
            *p = q + 1;
            return Some(Bracket::NotMatched);
        }
        first = false;
        if c == b'[' {
            let d = at(pat, q + 1);
            if d == b'.' || d == b'=' {
                return None;
            }
            if d == b':' {
                let body = pat.get(q + 2..).unwrap_or(&[]);
                let (i, key) = match body.first_chunk::<9>() {
                    Some(b) => class_name(b)?,
                    None => class_name(body)?,
                };
                q += 4 + i;
                match class_test_key(key, nv) {
                    None => return None,
                    Some(true) => {
                        *p = q;
                        return Some(Bracket::Matched);
                    }
                    Some(false) => continue,
                }
            }
        }
        let lo = fold(c, flags);
        let nx = at(pat, q + 1);
        if nx == b'-' && at(pat, q + 2) != 0 && at(pat, q + 2) != b']' {
            let h = at(pat, q + 2);
            if (h == b'\\' && !noescape) || (h == b'[' && at(pat, q + 3) == b'.') {
                return None;
            }
            let hi = fold(h, flags);
            q += 3;
            if lo <= fnc && fnc <= hi {
                *p = q;
                return Some(Bracket::Matched);
            }
            continue;
        }
        q += 1;
        if lo == fnc {
            *p = q;
            return Some(Bracket::Matched);
        }
    }
}

#[allow(unused_assignments)]
#[inline(never)]
fn bracket_members<T: Ch>(pat: &[T], p: &mut usize, s: &[T], n: usize, fnc: T, flags: c_int, adv: &mut usize) -> Bracket {
    let noescape = flags & FNM_NOESCAPE != 0;
    let mut loc = Loc { coll: None };
    let nv = at(s, n);
    let mut c = at(pat, *p);
    *p += 1;
    loop {
        let mut normal = false;
        let mut done_element = false;
        let mut cold: T = k(0);
        let mut cold_seq: u32 = 0;
        let mut is_seqval = false;
        if !noescape && c.v() == BSL {
            if at(pat, *p).v() == 0 {
                return Bracket::Fail;
            }
            c = fold(at(pat, *p), flags);
            *p += 1;
            normal = true;
        } else if c.v() == LBR && at(pat, *p).v() == b':' as u32 {
            let startp = *p;
            let mut name = [0u8; CHAR_CLASS_MAX_LENGTH + 1];
            let mut c1 = 0usize;
            let mut ok = true;
            loop {
                if c1 == CHAR_CLASS_MAX_LENGTH {
                    return Bracket::Fail;
                }
                *p += 1;
                c = at(pat, *p);
                if c.v() == b':' as u32 && at(pat, *p + 1).v() == b']' as u32 {
                    *p += 2;
                    break;
                }
                #[allow(clippy::almost_complete_range)]
                if !((b'a' as u32)..(b'z' as u32)).contains(&c.v()) {
                    *p = startp;
                    c = k(b'[');
                    ok = false;
                    break;
                }
                name[c1] = c.v() as u8;
                c1 += 1;
            }
            if !ok {
                normal = true;
            } else {
                match class_test(&name[..c1], nv) {
                    None => return Bracket::Fail,
                    Some(true) => return Bracket::Matched,
                    Some(false) => {}
                }
                c = at(pat, *p);
                *p += 1;
                done_element = true;
            }
        } else if c.v() == LBR && at(pat, *p).v() == b'=' as u32 {
            let startp = *p;
            *p += 1;
            c = at(pat, *p);
            let mut literal = false;
            let mut sym: T = k(0);
            if c.v() == 0 {
                literal = true;
            } else {
                sym = c;
                *p += 1;
                c = at(pat, *p);
                if c.v() != b'=' as u32 || at(pat, *p + 1).v() != b']' as u32 {
                    literal = true;
                }
            }
            if literal {
                *p = startp;
                c = k(b'[');
                normal = true;
            } else {
                *p += 2;
                if loc.nrules() == 0 {
                    if nv == sym {
                        return Bracket::Matched;
                    }
                } else if equiv_matches(sym, &s[n..]) {
                    return Bracket::Matched;
                }
                c = at(pat, *p);
                *p += 1;
                done_element = true;
            }
        } else if c.v() == 0 {
            return Bracket::Literal;
        } else if c.v() == LBR && at(pat, *p).v() == b'.' as u32 {
            let Some((name, c1)) = read_symbol(pat, p) else { return Bracket::Fail };
            let is_range = at(pat, *p).v() == b'-' as u32 && at(pat, *p + 1).v() != 0;
            if loc.nrules() == 0 {
                if c1 != 1 {
                    return Bracket::Fail;
                }
                if !is_range && nv == at(pat, name) {
                    return Bracket::Matched;
                }
                cold = at(pat, name);
                c = at(pat, *p);
                *p += 1;
            } else if let Some((seq, elen)) = find_symbol::<T>(loc.get(), &pat[name..name + c1]) {
                if !is_range {
                    let mut same = true;
                    for i in 0..elen {
                        if at(s, n + i).v() != at(pat, name + i).v() {
                            same = false;
                            break;
                        }
                    }
                    if same {
                        *adv = elen - 1;
                        return Bracket::Matched;
                    }
                }
                is_seqval = true;
                cold_seq = as_cold::<T>(seq);
                c = at(pat, *p);
                *p += 1;
            } else if c1 == 1 {
                if !is_range && nv == at(pat, name) {
                    return Bracket::Matched;
                }
                cold = at(pat, name);
                c = at(pat, *p);
                *p += 1;
            } else {
                return Bracket::Fail;
            }
        } else {
            c = fold(c, flags);
            normal = true;
        }
        if normal {
            let is_range = at(pat, *p).v() == b'-' as u32 && at(pat, *p + 1).v() != 0 && at(pat, *p + 1).v() != b']' as u32;
            if !is_range && c == fnc {
                return Bracket::Matched;
            }
            is_seqval = false;
            cold = c;
            c = at(pat, *p);
            *p += 1;
        }
        if !done_element && c.v() == b'-' as u32 && at(pat, *p).v() != b']' as u32 {
            let mut cend = at(pat, *p);
            *p += 1;
            let fcollseq = seq_of(loc.get(), fnc);
            'range: {
                if T::WIDE && fcollseq == NO_SEQ {
                    break 'range;
                }
                let lcollseq = if is_seqval { cold_seq } else { seq_of(loc.get(), cold) };
                let mut cend_seq = 0u32;
                is_seqval = false;
                if cend.v() == LBR && at(pat, *p).v() == b'.' as u32 {
                    let Some((name, c1)) = read_symbol(pat, p) else { return Bracket::Fail };
                    if loc.nrules() == 0 {
                        if c1 != 1 {
                            return Bracket::Fail;
                        }
                        cend = at(pat, name);
                    } else if let Some((seq, _)) = find_symbol::<T>(loc.get(), &pat[name..name + c1]) {
                        is_seqval = true;
                        cend_seq = as_cend::<T>(seq);
                    } else if c1 == 1 {
                        cend = at(pat, name);
                        c = at(pat, *p);
                        *p += 1;
                    } else {
                        return Bracket::Fail;
                    }
                } else {
                    if !noescape && cend.v() == BSL {
                        cend = at(pat, *p);
                        *p += 1;
                    }
                    if cend.v() == 0 {
                        return Bracket::Fail;
                    }
                    cend = fold(cend, flags);
                }
                if (T::WIDE && lcollseq == u32::MAX) || lcollseq <= fcollseq {
                    let hcollseq = if is_seqval {
                        cend_seq
                    } else {
                        let h = seq_of(loc.get(), cend);
                        if T::WIDE && h == NO_SEQ {
                            if lcollseq != fcollseq {
                                break 'range;
                            }
                            return Bracket::Matched;
                        }
                        h
                    };
                    if lcollseq <= hcollseq && fcollseq <= hcollseq {
                        return Bracket::Matched;
                    }
                }
            }
            c = at(pat, *p);
            *p += 1;
        }
        if c.v() == b']' as u32 {
            return Bracket::NotMatched;
        }
    }
}

#[inline]
fn skip_rest<T: Ch>(pat: &[T], p: &mut usize, flags: c_int) -> Result<bool, ()> {
    let noescape = flags & FNM_NOESCAPE != 0;
    loop {
        let c = at(pat, *p).v();
        *p += 1;
        if c == b']' as u32 {
            return Ok(false);
        }
        if c == 0 {
            return Ok(true);
        }
        if !noescape && c == BSL {
            if at(pat, *p).v() == 0 {
                return Err(());
            }
            *p += 1;
        } else if c == LBR && at(pat, *p).v() == b':' as u32 {
            let startp = *p;
            let mut c1 = 0;
            loop {
                *p += 1;
                let cc = at(pat, *p).v();
                c1 += 1;
                if c1 == CHAR_CLASS_MAX_LENGTH {
                    return Err(());
                }
                if at(pat, *p).v() == b':' as u32 && at(pat, *p + 1).v() == b']' as u32 {
                    break;
                }
                #[allow(clippy::almost_complete_range)]
                if !((b'a' as u32)..(b'z' as u32)).contains(&cc) {
                    *p = startp.wrapping_sub(2);
                    break;
                }
            }
            *p = p.wrapping_add(2);
        } else if c == LBR && at(pat, *p).v() == b'=' as u32 {
            *p += 1;
            if at(pat, *p).v() == 0 {
                return Err(());
            }
            *p += 1;
            if at(pat, *p).v() != b'=' as u32 || at(pat, *p + 1).v() != b']' as u32 {
                return Err(());
            }
            *p += 2;
        } else if c == LBR && at(pat, *p).v() == b'.' as u32 {
            loop {
                *p += 1;
                let cc = at(pat, *p).v();
                if cc == 0 {
                    return Err(());
                }
                if cc == b'.' as u32 && at(pat, *p + 1).v() == b']' as u32 {
                    break;
                }
            }
            *p += 2;
        }
    }
}

#[inline]
fn memchr<T: Ch>(s: &[T], from: usize, c: T, end: usize) -> Option<usize> {
    if from >= end {
        return None;
    }
    let hay = &s[from..end];
    if let Some(b) = T::bytes(hay)
        && b.len() > 12
    {
        let r = unsafe { rusty_libc_mem::memchr(b.as_ptr().cast(), c.v() as i32, b.len()) } as usize;
        return if r == 0 { None } else { Some(from + (r - b.as_ptr() as usize)) };
    }
    hay.iter().position(|&x| x == c).map(|i| from + i)
}

fn end_pattern<T: Ch>(pat: &[T], pattern: usize) -> usize {
    let mut p = pattern;
    loop {
        p += 1;
        let c = at(pat, p).v();
        if c == 0 {
            return pattern;
        } else if c == LBR {
            let pc = posixly();
            p += 1;
            if at(pat, p).v() == BANG || (pc < 0 && at(pat, p).v() == b'^' as u32) {
                p += 1;
            }
            if at(pat, p).v() == b']' as u32 {
                p += 1;
            }
            while at(pat, p).v() != b']' as u32 {
                let x = at(pat, p).v();
                p += 1;
                if x == 0 {
                    return pattern;
                }
            }
        } else if matches!(c, QM | STAR | PLUS | AT | BANG) && at(pat, p + 1).v() == b'(' as u32 {
            p = end_pattern(pat, p + 1);
            if at(pat, p).v() == 0 {
                return pattern;
            }
        } else if c == b')' as u32 {
            break;
        }
    }
    p + 1
}

type Item = (usize, usize);

struct Alts {
    inline: [Item; 8],
    n: usize,
    more: CVec<Item>,
}

impl Alts {
    #[inline]
    fn new() -> Alts {
        Alts { inline: [(0, 0); 8], n: 0, more: CVec::new() }
    }
    #[inline]
    fn len(&self) -> usize {
        self.n
    }
    #[inline]
    fn item(&self, i: usize) -> Item {
        if i < 8 { self.inline[i] } else { self.more.as_slice()[i - 8] }
    }
    #[inline]
    fn push(&mut self, it: Item) -> bool {
        if self.n < 8 {
            self.inline[self.n] = it;
        } else if !self.more.push(it) {
            return false;
        }
        self.n += 1;
        true
    }
    #[inline]
    fn get<'p, T: Ch>(&self, pat: &'p [T], i: usize) -> &'p [T] {
        let (o, l) = self.item(i);
        &pat[o..o + l]
    }
}

#[allow(clippy::too_many_arguments)]
fn ext_cat<T: Ch>(buf: &mut [T], list: &Alts, pat: &[T], rest: &[T], s: &[T], string: usize, string_end: usize, nlp: bool, flags2: c_int) -> c_int {
    let mut heap = CVec::<T>::new();
    for i in 0..list.len() {
        let item = list.get(pat, i);
        let len = item.len() + rest.len();
        let cat: &mut [T] = if len <= buf.len() {
            &mut buf[..len]
        } else {
            if !heap.resize(len, k(0)) {
                return -2;
            }
            &mut heap.as_mut_slice()[..len]
        };
        cat[..item.len()].copy_from_slice(item);
        cat[item.len()..].copy_from_slice(rest);
        if fct(cat, 0, s, string, string_end, nlp, flags2, None) == 0 {
            return 0;
        }
    }
    FNM_NOMATCH
}

#[allow(clippy::too_many_arguments)]
fn ext_match<T: Ch>(opt: u32, pat: &[T], pattern: usize, s: &[T], string: usize, string_end: usize, nlp: bool, flags: c_int) -> c_int {
    let mut list = Alts::new();
    let mut level: isize = 0;
    let mut startp = pattern + 1;
    let mut p = startp;
    let mut longest = 0usize;
    while level >= 0 {
        let c = at(pat, p).v();
        if c == 0 {
            return -1;
        } else if c == LBR {
            let pc = posixly();
            p += 1;
            if at(pat, p).v() == BANG || (pc < 0 && at(pat, p).v() == b'^' as u32) {
                p += 1;
            }
            if at(pat, p).v() == b']' as u32 {
                p += 1;
            }
            while at(pat, p).v() != b']' as u32 {
                let x = at(pat, p).v();
                p += 1;
                if x == 0 {
                    return -1;
                }
            }
        } else if matches!(c, QM | STAR | PLUS | AT | BANG) && at(pat, p + 1).v() == b'(' as u32 {
            level += 1;
        } else if c == b')' as u32 || c == b'|' as u32 {
            if level == 0 {
                if !list.push((startp, p - startp)) {
                    return -2;
                }
                longest = longest.max(p - startp);
                if c == b'|' as u32 {
                    startp = p + 1;
                }
            }
            if c == b')' as u32 {
                level -= 1;
            }
        }
        p += 1;
    }
    let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
    let after = |rs: usize| -> bool { if rs == string { nlp } else { at(s, rs - 1).v() == SLASH && no_leading_period(flags) } };
    let nitems = list.len();
    match opt {
        STAR | PLUS => {
            if opt == STAR && fct(pat, p, s, string, string_end, nlp, flags, None) == 0 {
                return 0;
            }
            for i in 0..nitems {
                let item = list.get(pat, i);
                let mut rs = string;
                while rs <= string_end {
                    if fct(item, 0, s, string, rs, nlp, flags2, None) == 0
                        && (fct(pat, p, s, rs, string_end, after(rs), flags2, None) == 0 || (rs != string && fct(pat, pattern - 1, s, rs, string_end, after(rs), flags2, None) == 0))
                    {
                        return 0;
                    }
                    rs += 1;
                }
            }
            FNM_NOMATCH
        }
        QM | AT => {
            if opt == QM && fct(pat, p, s, string, string_end, nlp, flags, None) == 0 {
                return 0;
            }
            let rest_end = p + pat[p..].iter().position(|c| c.v() == 0).unwrap_or(pat.len() - p);
            let rest = &pat[p..rest_end];
            let need = longest + rest.len();
            if need <= 64 {
                ext_cat(&mut [k::<T>(0); 64], &list, pat, rest, s, string, string_end, nlp, flags2)
            } else if need <= 512 {
                ext_cat(&mut [k::<T>(0); 512], &list, pat, rest, s, string, string_end, nlp, flags2)
            } else {
                ext_cat(&mut [], &list, pat, rest, s, string, string_end, nlp, flags2)
            }
        }
        BANG => {
            let mut rs = string;
            while rs <= string_end {
                let mut any = false;
                for i in 0..nitems {
                    if fct(list.get(pat, i), 0, s, string, rs, nlp, flags2, None) == 0 {
                        any = true;
                        break;
                    }
                }
                if !any && fct(pat, p, s, rs, string_end, after(rs), flags2, None) == 0 {
                    return 0;
                }
                rs += 1;
            }
            FNM_NOMATCH
        }
        _ => -1,
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn fct<T: Ch>(pat: &[T], p0: usize, s: &[T], n0: usize, string_end: usize, mut no_leading_period_: bool, flags: c_int, mut ends: Option<&mut Ends>) -> c_int {
    let mut p = p0;
    let mut n = n0;
    let extmatch = flags & FNM_EXTMATCH != 0;
    let slash_special = no_leading_period(flags);
    let sv = &s[..string_end];
    loop {
        {
            let mut m = 0usize;
            if !T::WIDE && flags & FNM_CASEFOLD != 0 && !rusty_libc_core::locale::ctype_special() {
                let pr = &pat[p.min(pat.len())..];
                let nr = &sv[n.min(sv.len())..];
                let lower = |v: u32| if v.wrapping_sub(65) < 26 { v | 32 } else { v };
                for (&pc, &nc) in pr.iter().zip(nr) {
                    let (pc, nc) = (pc.v(), nc.v());
                    if pc == QM && !extmatch && (m != 0 || !no_leading_period_) && !(flags & FNM_FILE_NAME != 0 && nc == SLASH) {
                        m += 1;
                        continue;
                    }
                    if pc == 0 || (pc < 128 && SPECIAL[pc as usize]) || (pc == SLASH && slash_special) {
                        break;
                    }
                    if pc != nc && (pc >= 128 || nc >= 128 || lower(pc) != lower(nc)) {
                        break;
                    }
                    m += 1;
                }
            } else if flags & FNM_CASEFOLD == 0 {
                let qm_ok = !extmatch;
                let nlp0 = no_leading_period_;
                let fname = flags & FNM_FILE_NAME != 0;
                let pr = pat.get(p..).unwrap_or(&[]);
                let nr = sv.get(n..).unwrap_or(&[]);
                for (&pc, &nc) in pr.iter().zip(nr) {
                    let (pc, nc) = (pc.v(), nc.v());
                    if pc == nc && !(pc < 128 && STOP[pc as usize]) && !(pc == SLASH && slash_special) {
                        m += 1;
                        continue;
                    }
                    if pc == QM && qm_ok && (m != 0 || !nlp0) && !(fname && nc == SLASH) {
                        m += 1;
                        continue;
                    }
                    break;
                }
            } else {
                let pr = &pat[p.min(pat.len())..];
                let nr = &sv[n.min(sv.len())..];
                for (&praw, &nraw) in pr.iter().zip(nr) {
                    let pc = praw.v();
                    if pc == QM && !extmatch && (m != 0 || !no_leading_period_) && !(flags & FNM_FILE_NAME != 0 && nraw.v() == SLASH) {
                        m += 1;
                        continue;
                    }
                    if pc == 0 || (pc < 128 && SPECIAL[pc as usize]) || (pc == SLASH && slash_special) || fold(praw, flags) != fold(nraw, flags) {
                        break;
                    }
                    m += 1;
                }
            }
            if m != 0 {
                p += m;
                n += m;
                no_leading_period_ = false;
            }
        }
        let mut c = at(pat, p);
        p += 1;
        if c.v() == 0 {
            break;
        }
        let mut new_nlp = false;
        c = fold(c, flags);
        let mut normal = false;
        match c.v() {
            QM => {
                if extmatch && at(pat, p).v() == b'(' as u32 {
                    let res = ext_match(c.v(), pat, p, s, n, string_end, no_leading_period_, flags);
                    if res != -1 {
                        return res;
                    }
                }
                if n == string_end || (at(s, n).v() == SLASH && flags & FNM_FILE_NAME != 0) || (at(s, n).v() == b'.' as u32 && no_leading_period_) {
                    return FNM_NOMATCH;
                }
            }
            BSL => {
                if flags & FNM_NOESCAPE == 0 {
                    c = at(pat, p);
                    p += 1;
                    if c.v() == 0 {
                        return FNM_NOMATCH;
                    }
                    c = fold(c, flags);
                }
                if n == string_end || fold(at(s, n), flags) != c {
                    return FNM_NOMATCH;
                }
            }
            STAR => {
                if extmatch && at(pat, p).v() == b'(' as u32 {
                    let res = ext_match(c.v(), pat, p, s, n, string_end, no_leading_period_, flags);
                    if res != -1 {
                        return res;
                    }
                } else if let Some(e) = ends.as_deref_mut() {
                    e.pattern = Some(p - 1);
                    e.string = n;
                    e.no_leading_period = no_leading_period_;
                    return 0;
                }
                if n != string_end && at(s, n).v() == b'.' as u32 && no_leading_period_ {
                    return FNM_NOMATCH;
                }
                c = at(pat, p);
                p += 1;
                while c.v() == QM || c.v() == STAR {
                    if at(pat, p).v() == b'(' as u32 && extmatch {
                        let endp = end_pattern(pat, p);
                        if endp != p {
                            p = endp;
                            c = at(pat, p);
                            p += 1;
                            continue;
                        }
                    }
                    if c.v() == QM {
                        if n == string_end || (at(s, n).v() == SLASH && flags & FNM_FILE_NAME != 0) {
                            return FNM_NOMATCH;
                        }
                        n += 1;
                    }
                    c = at(pat, p);
                    p += 1;
                }
                if c.v() == 0 {
                    return if flags & FNM_FILE_NAME == 0 || flags & FNM_LEADING_DIR != 0 || memchr(s, n, k(b'/'), string_end).is_none() { 0 } else { FNM_NOMATCH };
                }
                let mut end = Ends { pattern: None, string: 0, no_leading_period: false };
                let endp = if flags & FNM_FILE_NAME != 0 && c.v() != SLASH { memchr(s, n, k(b'/'), string_end) } else { None }.unwrap_or(string_end);
                let mut found = false;
                if c.v() == LBR || (extmatch && (c.v() == AT || c.v() == PLUS || c.v() == BANG) && at(pat, p).v() == b'(' as u32) {
                    let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
                    p -= 1;
                    let pre = !T::WIDE && c.v() == LBR && at(pat, p + 1).v() != b'^' as u32 && byte_order_collation();
                    let neg = pre && at(pat, p + 1).v() == BANG;
                    let patb = T::bytes(pat);
                    while n < endp {
                        if pre && let Some(pb) = patb {
                            let mut bp = p + 1 + neg as usize;
                            let nc = fold(at(s, n), flags);
                            match bracket_fast(pb, &mut bp, nc.v() as u8, at(s, n).v() as u8, flags) {
                                Some(Bracket::NotMatched) if !neg => {
                                    n += 1;
                                    no_leading_period_ = false;
                                    continue;
                                }
                                Some(Bracket::Matched) if neg => {
                                    n += 1;
                                    no_leading_period_ = false;
                                    continue;
                                }
                                _ => {}
                            }
                        }
                        if fct(pat, p, s, n, string_end, no_leading_period_, flags2, Some(&mut end)) == 0 {
                            found = true;
                            break;
                        }
                        n += 1;
                        no_leading_period_ = false;
                    }
                } else if c.v() == SLASH && flags & FNM_FILE_NAME != 0 {
                    n = memchr(s, n, k(b'/'), string_end).unwrap_or(string_end);
                    if n < string_end && at(s, n).v() == SLASH {
                        if ends.is_none() {
                            n += 1;
                            no_leading_period_ = flags & FNM_PERIOD != 0;
                            continue;
                        }
                        if fct(pat, p, s, n + 1, string_end, flags & FNM_PERIOD != 0, flags, None) == 0 {
                            return 0;
                        }
                    }
                } else {
                    let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
                    if c.v() == BSL && flags & FNM_NOESCAPE == 0 {
                        c = at(pat, p);
                    }
                    c = fold(c, flags);
                    p -= 1;
                    while n < endp {
                        if flags & FNM_CASEFOLD == 0 {
                            let Some(q) = memchr(s, n, c, endp) else { break };
                            if q != n {
                                n = q;
                                no_leading_period_ = false;
                            }
                        }
                        if fold(at(s, n), flags) == c && fct(pat, p, s, n, string_end, no_leading_period_, flags2, Some(&mut end)) == 0 {
                            found = true;
                            break;
                        }
                        n += 1;
                        no_leading_period_ = false;
                    }
                }
                if found {
                    let Some(ep) = end.pattern else { return 0 };
                    p = ep;
                    n = end.string;
                    no_leading_period_ = end.no_leading_period;
                    continue;
                }
                return FNM_NOMATCH;
            }
            LBR => {
                let p_init = p;
                let n_init = n;
                let pc = posixly();
                if n == string_end {
                    return FNM_NOMATCH;
                }
                if at(s, n).v() == b'.' as u32 && no_leading_period_ {
                    return FNM_NOMATCH;
                }
                if at(s, n).v() == SLASH && flags & FNM_FILE_NAME != 0 {
                    return FNM_NOMATCH;
                }
                let not = at(pat, p).v() == BANG || (pc < 0 && at(pat, p).v() == b'^' as u32);
                if not {
                    p += 1;
                }
                let fnc = fold(at(s, n), flags);
                let mut literal = false;
                let mut adv = 0usize;
                let fast = match T::bytes(pat) {
                    Some(pb) if byte_order_collation() => {
                        let mut bp = p;
                        let r = bracket_fast(pb, &mut bp, fnc.v() as u8, at(s, n).v() as u8, flags);
                        if r.is_some() {
                            p = bp;
                        }
                        r
                    }
                    _ => None,
                };
                match fast.unwrap_or_else(|| bracket_members(pat, &mut p, s, n, fnc, flags, &mut adv)) {
                    Bracket::Fail => return FNM_NOMATCH,
                    Bracket::Literal => literal = true,
                    Bracket::NotMatched => {
                        if !not {
                            return FNM_NOMATCH;
                        }
                    }
                    Bracket::Matched => match skip_rest(pat, &mut p, flags) {
                        Err(()) => return FNM_NOMATCH,
                        Ok(true) => literal = true,
                        Ok(false) => {
                            if not {
                                return FNM_NOMATCH;
                            }
                            n += adv;
                        }
                    },
                }
                if literal {
                    p = p_init;
                    n = n_init;
                    c = k(b'[');
                    normal = true;
                }
            }
            PLUS | AT | BANG => {
                if extmatch && at(pat, p).v() == b'(' as u32 {
                    let res = ext_match(c.v(), pat, p, s, n, string_end, no_leading_period_, flags);
                    if res != -1 {
                        return res;
                    }
                }
                normal = true;
            }
            SLASH => {
                if no_leading_period(flags) {
                    if n == string_end || c != at(s, n) {
                        return FNM_NOMATCH;
                    }
                    new_nlp = true;
                } else {
                    normal = true;
                }
            }
            _ => normal = true,
        }
        if normal && (n == string_end || c != fold(at(s, n), flags)) {
            return FNM_NOMATCH;
        }
        no_leading_period_ = new_nlp;
        n += 1;
    }
    if n == string_end {
        return 0;
    }
    if flags & FNM_LEADING_DIR != 0 && at(s, n).v() == SLASH {
        return 0;
    }
    FNM_NOMATCH
}

enum Wide<'a> {
    Stack(&'a [u32]),
    Heap(CVec<u32>),
}

impl Wide<'_> {
    fn get(&self) -> &[u32] {
        match self {
            Wide::Stack(s) => s,
            Wide::Heap(h) => h.as_slice(),
        }
    }
}

fn to_wide<'a>(s: &[u8], stack: &'a mut [u32; 256]) -> Option<Wide<'a>> {
    use rusty_libc_wchar::mbstate_t;
    use rusty_libc_wchar::mbyte::mbsrtowcs;
    debug_assert!(s.last() == Some(&0));
    let conv = |dst: *mut u32, len: usize| -> (usize, bool) {
        let mut ps = mbstate_t::default();
        let mut src = s.as_ptr() as *const c_char;
        let r = unsafe { mbsrtowcs(dst.cast(), &mut src, len, &mut ps) };
        (r, src.is_null())
    };
    let (r, done) = conv(stack.as_mut_ptr(), stack.len());
    if r == usize::MAX {
        return None;
    }
    if done {
        return Some(Wide::Stack(&stack[..=r]));
    }
    let (n, _) = conv(core::ptr::null_mut(), 0);
    if n == usize::MAX {
        return None;
    }
    let mut buf = CVec::<u32>::new();
    if !buf.resize(n + 1, 0) {
        return None;
    }
    conv(buf.as_mut_ptr(), n + 1);
    Some(Wide::Heap(buf))
}

pub fn fnmatch_bytes(pattern: &[u8], string: &[u8], flags: c_int) -> c_int {
    debug_assert!(pattern.last() == Some(&0) && string.last() == Some(&0));
    unsafe { fnmatch_in(pattern.as_ptr(), Some(pattern), string, flags) }
}

#[inline(always)]
unsafe fn fnmatch_in(pattern: *const u8, known: Option<&[u8]>, string: &[u8], flags: c_int) -> c_int {
    let slen = string.len() - 1;
    let pat = || {
        known.unwrap_or_else(|| unsafe { rusty_libc_core::ffi::cstr_nonnull(pattern) }.to_bytes_with_nul())
    };
    if rusty_libc_wchar::mbyte::mb_cur_max() != 1 {
        let p = pat();
        if !(flags & FNM_CASEFOLD == 0 && string.is_ascii() && p.is_ascii()) && wide_match(p, string, flags) {
            return 0;
        }
    }
    if flags & !(FNM_NOESCAPE | FNM_CASEFOLD) == 0
        && let Some(r) = unsafe { simple_match(pattern, &string[..slen], flags & FNM_CASEFOLD != 0) }
    {
        return r;
    }
    fct::<u8>(pat(), 0, string, 0, slen, flags & FNM_PERIOD != 0, flags, None)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int {
    let s = unsafe { rusty_libc_core::ffi::cstr_nonnull(string) };
    unsafe { fnmatch_in(pattern.cast(), None, s.to_bytes_with_nul(), flags) }
}

#[inline(always)]
unsafe fn simple_match(pattern: *const u8, s: &[u8], casefold: bool) -> Option<c_int> {
    if casefold && rusty_libc_core::locale::ctype_special() {
        return None;
    }
    let byte = |i: usize| {
        unsafe { *pattern.wrapping_add(i) }
    };
    let star = byte(0) == b'*';
    let base = star as usize;
    let mut l = 0usize;
    let mut trailing = false;
    loop {
        let c = byte(base + l);
        if c == 0 {
            break;
        }
        if c == b'*' && !star && byte(base + l + 1) == 0 {
            trailing = true;
            break;
        }
        if c >= 128 || c == b'?' || c == b'*' || c == b'[' || c == b'\\' {
            return None;
        }
        l += 1;
    }
    let lit = unsafe { rusty_libc_core::ffi::bytes(pattern.wrapping_add(base), l) };
    let slen = s.len();
    let t = if trailing {
        s.get(..l)
    } else if star {
        s.get(slen.wrapping_sub(l)..)
    } else if slen == l {
        Some(s)
    } else {
        None
    };
    let Some(t) = t else { return Some(FNM_NOMATCH) };
    let same = if !casefold { eq_bytes(lit, t) } else { eq_ascii_casefold(lit, t) };
    Some(if same { 0 } else { FNM_NOMATCH })
}

#[inline(always)]
fn eq_ascii_casefold(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().min(b.len());
    let (a, b) = (&a[..n], &b[..n]);
    for i in 0..n {
        let (x, y) = (a[i], b[i]);
        if x != y && !(y < 128 && x.eq_ignore_ascii_case(&y)) {
            return false;
        }
    }
    true
}

#[inline(always)]
fn eq_bytes(a: &[u8], b: &[u8]) -> bool {
    let (ac, ar) = a.as_chunks::<8>();
    let (bc, br) = b.as_chunks::<8>();
    ac.iter().zip(bc).all(|(x, y)| u64::from_ne_bytes(*x) == u64::from_ne_bytes(*y)) && ar.iter().zip(br).all(|(x, y)| x == y)
}

#[inline(never)]
fn wide_match(pattern: &[u8], s: &[u8], flags: c_int) -> bool {
    let mut pstack = [0u32; 256];
    let mut sstack = [0u32; 256];
    let mut r = FNM_NOMATCH;
    if let Some(wp) = to_wide(pattern, &mut pstack)
        && let Some(ws) = to_wide(s, &mut sstack)
    {
        let (wp, ws) = (wp.get(), ws.get());
        r = fct::<u32>(wp, 0, ws, 0, ws.len() - 1, flags & FNM_PERIOD != 0, flags, None);
    }
    r == 0
}

pub fn matches(pattern: &core::ffi::CStr, string: &core::ffi::CStr, flags: c_int) -> bool {
    fnmatch_bytes(pattern.to_bytes_with_nul(), string.to_bytes_with_nul(), flags) == 0
}

