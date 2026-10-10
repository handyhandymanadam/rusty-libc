use core::ffi::{c_char, c_int};
use core::ptr::{null, null_mut};
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

static mut POSIXLY_CORRECT: i32 = 0;

fn posixly() -> i32 {
    unsafe {
        if POSIXLY_CORRECT == 0 {
            POSIXLY_CORRECT = if rusty_libc_core::env::getenv(b"POSIXLY_CORRECT").is_null() { -1 } else { 1 };
        }
        POSIXLY_CORRECT
    }
}

trait Ch: Copy + PartialEq + 'static {
    const WIDE: bool;
    fn v(self) -> u32;
    fn of(v: u32) -> Self;
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
}

#[inline(always)]
fn k<T: Ch>(b: u8) -> T {
    T::of(b as u32)
}

const QM: u32 = b'?' as u32;
const STAR: u32 = b'*' as u32;
const BSL: u32 = b'\\' as u32;
const LBR: u32 = b'[' as u32;
const PLUS: u32 = b'+' as u32;
const AT: u32 = b'@' as u32;
const BANG: u32 = b'!' as u32;
const SLASH: u32 = b'/' as u32;

type P<T> = *const T;

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
unsafe fn at<T: Ch>(p: P<T>, i: usize) -> T {
    unsafe { *p.add(i) }
}

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

struct Ends<T> {
    pattern: P<T>,
    string: P<T>,
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

unsafe fn equiv_matches<T: Ch>(s: T, n: P<T>) -> bool {
    unsafe {
        if T::WIDE {
            let pat = [s.v(), 0u32];
            let Some((rule, w, _)) = rusty_libc_locale::primary_wc(pat.as_ptr()) else { return false };
            let Some((rule2, w2, _)) = rusty_libc_locale::primary_wc(n as *const u32) else { return false };
            rule == rule2 && w.len() == w2.len() && w == w2
        } else {
            let pat = [s.v() as u8, 0u8];
            let Some((rule, w, _)) = rusty_libc_locale::primary_mb(pat.as_ptr()) else { return false };
            let Some((rule2, w2, _)) = rusty_libc_locale::primary_mb(n as *const u8) else { return false };
            rule == rule2 && w.len() == w2.len() && w == w2
        }
    }
}

unsafe fn read_symbol<T: Ch>(p: &mut P<T>) -> Option<(P<T>, usize)> {
    unsafe {
        let startp = *p;
        let mut c1 = 0usize;
        loop {
            *p = p.add(1);
            let c = at(*p, 0);
            if c.v() == b'.' as u32 && at(*p, 1).v() == b']' as u32 {
                *p = p.add(2);
                break;
            }
            if c.v() == 0 {
                return None;
            }
            c1 += 1;
        }
        Some((startp.add(1), c1))
    }
}

unsafe fn find_symbol<T: Ch>(coll: &Collation, name: P<T>, len: usize) -> Option<(u32, usize)> {
    unsafe {
        if T::WIDE {
            let sl = core::slice::from_raw_parts(name as *const u32, len);
            coll.symbol_by_wide(sl).map(|(seq, e)| (seq, e.len()))
        } else {
            let sl = core::slice::from_raw_parts(name as *const u8, len);
            coll.symbol_by_bytes(sl).map(|(seq, e)| (seq, e.len()))
        }
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
    let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_COLLATE);
    d.is_null() || unsafe { (*d).flags } & rusty_libc_core::locale::F_BUILTIN_C != 0
}

#[allow(clippy::almost_complete_range)]
unsafe fn bracket_fast(p: &mut *const u8, fnc: u8, nv: u8, flags: c_int) -> Option<Bracket> {
    unsafe {
        let noescape = flags & FNM_NOESCAPE != 0;
        let mut q = *p;
        let mut first = true;
        loop {
            let c = *q;
            if c == 0 || (c == b'\\' && !noescape) {
                return None;
            }
            if c == b']' && !first {
                *p = q.add(1);
                return Some(Bracket::NotMatched);
            }
            first = false;
            if c == b'[' {
                let d = *q.add(1);
                if d == b'.' || d == b'=' {
                    return None;
                }
                if d == b':' {
                    let mut name = [0u8; 8];
                    let mut i = 0;
                    loop {
                        let x = *q.add(2 + i);
                        if x == b':' && *q.add(3 + i) == b']' {
                            break;
                        }
                        if !(b'a'..b'z').contains(&x) || i == 7 {
                            return None;
                        }
                        name[i] = x;
                        i += 1;
                    }
                    q = q.add(4 + i);
                    match class_test::<u8>(&name[..i], nv) {
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
            let nx = *q.add(1);
            if nx == b'-' && *q.add(2) != 0 && *q.add(2) != b']' {
                let h = *q.add(2);
                if (h == b'\\' && !noescape) || (h == b'[' && *q.add(3) == b'.') {
                    return None;
                }
                let hi = fold(h, flags);
                q = q.add(3);
                if lo <= fnc && fnc <= hi {
                    *p = q;
                    return Some(Bracket::Matched);
                }
                continue;
            }
            q = q.add(1);
            if lo == fnc {
                *p = q;
                return Some(Bracket::Matched);
            }
        }
    }
}

#[allow(unused_assignments)]
unsafe fn bracket_members<T: Ch>(p: &mut P<T>, n: P<T>, fnc: T, flags: c_int, adv: &mut usize) -> Bracket {
    unsafe {
        let noescape = flags & FNM_NOESCAPE != 0;
        let mut loc = Loc { coll: None };
        let nv = at(n, 0);
        let mut c = at(*p, 0);
        *p = p.add(1);
        loop {
            let mut normal = false;
            let mut done_element = false;
            let mut cold: T = k(0);
            let mut cold_seq: u32 = 0;
            let mut is_seqval = false;
            if !noescape && c.v() == BSL {
                if at(*p, 0).v() == 0 {
                    return Bracket::Fail;
                }
                c = fold(at(*p, 0), flags);
                *p = p.add(1);
                normal = true;
            } else if c.v() == LBR && at(*p, 0).v() == b':' as u32 {
                let startp = *p;
                let mut name = [0u8; CHAR_CLASS_MAX_LENGTH + 1];
                let mut c1 = 0usize;
                let mut ok = true;
                loop {
                    if c1 == CHAR_CLASS_MAX_LENGTH {
                        return Bracket::Fail;
                    }
                    *p = p.add(1);
                    c = at(*p, 0);
                    if c.v() == b':' as u32 && at(*p, 1).v() == b']' as u32 {
                        *p = p.add(2);
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
                    c = at(*p, 0);
                    *p = p.add(1);
                    done_element = true;
                }
            } else if c.v() == LBR && at(*p, 0).v() == b'=' as u32 {
                let startp = *p;
                *p = p.add(1);
                c = at(*p, 0);
                let mut literal = false;
                let mut s: T = k(0);
                if c.v() == 0 {
                    literal = true;
                } else {
                    s = c;
                    *p = p.add(1);
                    c = at(*p, 0);
                    if c.v() != b'=' as u32 || at(*p, 1).v() != b']' as u32 {
                        literal = true;
                    }
                }
                if literal {
                    *p = startp;
                    c = k(b'[');
                    normal = true;
                } else {
                    *p = p.add(2);
                    if loc.nrules() == 0 {
                        if nv == s {
                            return Bracket::Matched;
                        }
                    } else if equiv_matches(s, n) {
                        return Bracket::Matched;
                    }
                    c = at(*p, 0);
                    *p = p.add(1);
                    done_element = true;
                }
            } else if c.v() == 0 {
                return Bracket::Literal;
            } else if c.v() == LBR && at(*p, 0).v() == b'.' as u32 {
                let Some((name, c1)) = read_symbol(p) else { return Bracket::Fail };
                let is_range = at(*p, 0).v() == b'-' as u32 && at(*p, 1).v() != 0;
                if loc.nrules() == 0 {
                    if c1 != 1 {
                        return Bracket::Fail;
                    }
                    if !is_range && nv == at(name, 0) {
                        return Bracket::Matched;
                    }
                    cold = at(name, 0);
                    c = at(*p, 0);
                    *p = p.add(1);
                } else if let Some((seq, elen)) = find_symbol::<T>(loc.get(), name, c1) {
                    if !is_range {
                        let mut same = true;
                        for i in 0..elen {
                            if at(n, i).v() != at(name, i).v() {
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
                    c = at(*p, 0);
                    *p = p.add(1);
                } else if c1 == 1 {
                    if !is_range && nv == at(name, 0) {
                        return Bracket::Matched;
                    }
                    cold = at(name, 0);
                    c = at(*p, 0);
                    *p = p.add(1);
                } else {
                    return Bracket::Fail;
                }
            } else {
                c = fold(c, flags);
                normal = true;
            }
            if normal {
                let is_range = at(*p, 0).v() == b'-' as u32 && at(*p, 1).v() != 0 && at(*p, 1).v() != b']' as u32;
                if !is_range && c == fnc {
                    return Bracket::Matched;
                }
                is_seqval = false;
                cold = c;
                c = at(*p, 0);
                *p = p.add(1);
            }
            if !done_element && c.v() == b'-' as u32 && at(*p, 0).v() != b']' as u32 {
                let mut cend = at(*p, 0);
                *p = p.add(1);
                let fcollseq = seq_of(loc.get(), fnc);
                'range: {
                    if T::WIDE && fcollseq == NO_SEQ {
                        break 'range;
                    }
                    let lcollseq = if is_seqval { cold_seq } else { seq_of(loc.get(), cold) };
                    let mut cend_seq = 0u32;
                    is_seqval = false;
                    if cend.v() == LBR && at(*p, 0).v() == b'.' as u32 {
                        let Some((name, c1)) = read_symbol(p) else { return Bracket::Fail };
                        if loc.nrules() == 0 {
                            if c1 != 1 {
                                return Bracket::Fail;
                            }
                            cend = at(name, 0);
                        } else if let Some((seq, _)) = find_symbol::<T>(loc.get(), name, c1) {
                            is_seqval = true;
                            cend_seq = as_cend::<T>(seq);
                        } else if c1 == 1 {
                            cend = at(name, 0);
                            c = at(*p, 0);
                            *p = p.add(1);
                        } else {
                            return Bracket::Fail;
                        }
                    } else {
                        if !noescape && cend.v() == BSL {
                            cend = at(*p, 0);
                            *p = p.add(1);
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
                c = at(*p, 0);
                *p = p.add(1);
            }
            if c.v() == b']' as u32 {
                return Bracket::NotMatched;
            }
        }
    }
}

unsafe fn skip_rest<T: Ch>(p: &mut P<T>, flags: c_int) -> Result<bool, ()> {
    unsafe {
        let noescape = flags & FNM_NOESCAPE != 0;
        loop {
            let c = at(*p, 0).v();
            *p = p.add(1);
            if c == b']' as u32 {
                return Ok(false);
            }
            if c == 0 {
                return Ok(true);
            }
            if !noescape && c == BSL {
                if at(*p, 0).v() == 0 {
                    return Err(());
                }
                *p = p.add(1);
            } else if c == LBR && at(*p, 0).v() == b':' as u32 {
                let startp = *p;
                let mut c1 = 0;
                loop {
                    *p = p.add(1);
                    let cc = at(*p, 0).v();
                    c1 += 1;
                    if c1 == CHAR_CLASS_MAX_LENGTH {
                        return Err(());
                    }
                    if at(*p, 0).v() == b':' as u32 && at(*p, 1).v() == b']' as u32 {
                        break;
                    }
                    #[allow(clippy::almost_complete_range)]
                    if !((b'a' as u32)..(b'z' as u32)).contains(&cc) {
                        *p = startp.sub(2);
                        break;
                    }
                }
                *p = p.add(2);
            } else if c == LBR && at(*p, 0).v() == b'=' as u32 {
                *p = p.add(1);
                if at(*p, 0).v() == 0 {
                    return Err(());
                }
                *p = p.add(1);
                if at(*p, 0).v() != b'=' as u32 || at(*p, 1).v() != b']' as u32 {
                    return Err(());
                }
                *p = p.add(2);
            } else if c == LBR && at(*p, 0).v() == b'.' as u32 {
                loop {
                    *p = p.add(1);
                    let cc = at(*p, 0).v();
                    if cc == 0 {
                        return Err(());
                    }
                    if cc == b'.' as u32 && at(*p, 1).v() == b']' as u32 {
                        break;
                    }
                }
                *p = p.add(2);
            }
        }
    }
}

unsafe fn memchr<T: Ch>(mut s: P<T>, c: T, end: P<T>) -> P<T> {
    unsafe {
        if !T::WIDE {
            if s >= end {
                return null();
            }
            if end as usize - s as usize <= 12 {
                while s < end {
                    if *s == c {
                        return s;
                    }
                    s = s.add(1);
                }
                return null();
            }
            let r = rusty_libc_mem::memchr(s.cast(), c.v() as i32, end as usize - s as usize) as *const u8;
            return r.cast();
        }
        while s < end {
            if *s == c {
                return s;
            }
            s = s.add(1);
        }
        null()
    }
}

unsafe fn end_pattern<T: Ch>(pattern: P<T>) -> P<T> {
    unsafe {
        let mut p = pattern;
        loop {
            p = p.add(1);
            let c = (*p).v();
            if c == 0 {
                return pattern;
            } else if c == LBR {
                let pc = posixly();
                p = p.add(1);
                if (*p).v() == BANG || (pc < 0 && (*p).v() == b'^' as u32) {
                    p = p.add(1);
                }
                if (*p).v() == b']' as u32 {
                    p = p.add(1);
                }
                while (*p).v() != b']' as u32 {
                    let x = (*p).v();
                    p = p.add(1);
                    if x == 0 {
                        return pattern;
                    }
                }
            } else if matches!(c, QM | STAR | PLUS | AT | BANG) && at(p, 1).v() == b'(' as u32 {
                p = end_pattern(p.add(1));
                if (*p).v() == 0 {
                    return pattern;
                }
            } else if c == b')' as u32 {
                break;
            }
        }
        p.add(1)
    }
}

struct StrList<T> {
    items: *mut *mut T,
    len: usize,
    cap: usize,
    inline: [*mut T; 8],
    lens: [usize; 8],
    arena: *mut T,
    acap: usize,
    aused: usize,
}

impl<T: Ch> StrList<T> {
    fn new(arena: *mut T, acap: usize) -> StrList<T> {
        StrList { items: null_mut(), len: 0, cap: 0, inline: [null_mut(); 8], lens: [usize::MAX; 8], arena, acap, aused: 0 }
    }
    unsafe fn alloc(&mut self, n: usize) -> *mut T {
        unsafe {
            if self.aused + n <= self.acap {
                let r = self.arena.add(self.aused);
                self.aused += n;
                return r;
            }
            rusty_libc_malloc::malloc(n.max(1) * core::mem::size_of::<T>()) as *mut T
        }
    }
    fn in_arena(&self, s: *mut T) -> bool {
        let a = self.arena as usize;
        (s as usize) >= a && (s as usize) < a + self.acap * core::mem::size_of::<T>()
    }
    unsafe fn push(&mut self, s: *mut T) -> bool {
        unsafe {
            if self.items.is_null() {
                self.items = self.inline.as_mut_ptr();
                self.cap = 8;
            }
            if self.len == self.cap {
                let ncap = self.cap * 2;
                let np = rusty_libc_malloc::malloc(ncap * core::mem::size_of::<*mut T>()) as *mut *mut T;
                if np.is_null() {
                    return false;
                }
                core::ptr::copy_nonoverlapping(self.items, np, self.len);
                if self.items != self.inline.as_mut_ptr() {
                    rusty_libc_malloc::free(self.items.cast());
                }
                self.items = np;
                self.cap = ncap;
            }
            *self.items.add(self.len) = s;
            self.len += 1;
            true
        }
    }
    unsafe fn len_of(&self, i: usize) -> usize {
        unsafe { if i < 8 && self.lens[i] != usize::MAX { self.lens[i] } else { cstrlen(*self.items.add(i)) } }
    }
    unsafe fn free(&mut self) {
        unsafe {
            for i in 0..self.len {
                let it = *self.items.add(i);
                if !self.in_arena(it) {
                    rusty_libc_malloc::free(it.cast());
                }
            }
            if !self.items.is_null() && self.items != self.inline.as_mut_ptr() {
                rusty_libc_malloc::free(self.items.cast());
            }
            self.items = null_mut();
            self.len = 0;
        }
    }
}

#[inline(always)]
unsafe fn copy_chars<T: Ch>(src: *const T, dst: *mut T, n: usize) {
    unsafe {
        if n <= 24 {
            for i in 0..n {
                core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
            }
        } else {
            core::ptr::copy_nonoverlapping(src, dst, n);
        }
    }
}

unsafe fn cstrlen<T: Ch>(p: P<T>) -> usize {
    unsafe {
        if T::WIDE {
            rusty_libc_wchar::wstring::wcslen(p.cast())
        } else {
            rusty_libc_mem::strlen(p.cast())
        }
    }
}

unsafe fn ext_match<T: Ch>(opt: u32, pattern: P<T>, string: P<T>, string_end: P<T>, nlp: bool, flags: c_int) -> c_int {
    unsafe {
        let mut arena = core::mem::MaybeUninit::<[T; 512]>::uninit();
        let mut list = StrList::<T>::new(arena.as_mut_ptr().cast(), 512);
        let mut level: isize = 0;
        let mut startp = pattern.add(1);
        let mut p = startp;
        let mut retval: c_int = 0;
        while level >= 0 {
            let c = (*p).v();
            if c == 0 {
                list.free();
                return -1;
            } else if c == LBR {
                let pc = posixly();
                p = p.add(1);
                if (*p).v() == BANG || (pc < 0 && (*p).v() == b'^' as u32) {
                    p = p.add(1);
                }
                if (*p).v() == b']' as u32 {
                    p = p.add(1);
                }
                while (*p).v() != b']' as u32 {
                    let x = (*p).v();
                    p = p.add(1);
                    if x == 0 {
                        list.free();
                        return -1;
                    }
                }
            } else if matches!(c, QM | STAR | PLUS | AT | BANG) && at(p, 1).v() == b'(' as u32 {
                level += 1;
            } else if c == b')' as u32 || c == b'|' as u32 {
                if level == 0 {
                    let slen = p.offset_from(startp) as usize + 1;
                    let newp = list.alloc(slen);
                    if newp.is_null() {
                        list.free();
                        return -2;
                    }
                    copy_chars(startp, newp, p.offset_from(startp) as usize);
                    *newp.add(p.offset_from(startp) as usize) = k(0);
                    if list.len < 8 {
                        list.lens[list.len] = p.offset_from(startp) as usize;
                    }
                    if !list.push(newp) {
                        if !list.in_arena(newp) {
                            rusty_libc_malloc::free(newp.cast());
                        }
                        list.free();
                        return -2;
                    }
                    if c == b'|' as u32 {
                        startp = p.add(1);
                    }
                }
                if c == b')' as u32 {
                    level -= 1;
                }
            }
            p = p.add(1);
        }
        let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
        let after = |rs: P<T>| -> bool { if rs == string { nlp } else { (*rs.sub(1)).v() == SLASH && no_leading_period(flags) } };
        let mut matched = false;
        match opt {
            STAR | PLUS => {
                if opt == STAR && fct(p, string, string_end, nlp, flags, null_mut()) == 0 {
                    matched = true;
                } else {
                    'outer: for i in 0..list.len {
                        let mut rs = string;
                        while rs <= string_end {
                            if fct(*list.items.add(i), string, rs, nlp, flags2, null_mut()) == 0
                                && (fct(p, rs, string_end, after(rs), flags2, null_mut()) == 0
                                    || (rs != string && fct(pattern.sub(1), rs, string_end, after(rs), flags2, null_mut()) == 0))
                            {
                                matched = true;
                                break 'outer;
                            }
                            rs = rs.add(1);
                        }
                    }
                    if !matched {
                        retval = FNM_NOMATCH;
                    }
                }
            }
            QM | AT => {
                if opt == QM && fct(p, string, string_end, nlp, flags, null_mut()) == 0 {
                    matched = true;
                } else {
                    let rest = cstrlen(p);
                    for i in 0..list.len {
                        let s = *list.items.add(i);
                        let l = list.len_of(i);
                        let buf = list.alloc(l + rest + 1);
                        if buf.is_null() {
                            list.free();
                            return -2;
                        }
                        copy_chars(s, buf, l);
                        if !list.in_arena(s) {
                            rusty_libc_malloc::free(s.cast());
                        }
                        *list.items.add(i) = buf;
                        copy_chars(p, buf.add(l), rest + 1);
                        if fct(buf, string, string_end, nlp, flags2, null_mut()) == 0 {
                            matched = true;
                            break;
                        }
                    }
                    if !matched {
                        retval = FNM_NOMATCH;
                    }
                }
            }
            BANG => {
                let mut rs = string;
                while rs <= string_end {
                    let mut any = false;
                    for i in 0..list.len {
                        if fct(*list.items.add(i), string, rs, nlp, flags2, null_mut()) == 0 {
                            any = true;
                            break;
                        }
                    }
                    if !any && fct(p, rs, string_end, after(rs), flags2, null_mut()) == 0 {
                        matched = true;
                        break;
                    }
                    rs = rs.add(1);
                }
                if !matched {
                    retval = FNM_NOMATCH;
                }
            }
            _ => retval = -1,
        }
        if matched {
            retval = 0;
        }
        list.free();
        retval
    }
}

unsafe fn fct<T: Ch>(pattern: P<T>, string: P<T>, string_end: P<T>, mut no_leading_period_: bool, flags: c_int, ends: *mut Ends<T>) -> c_int {
    unsafe {
        let mut p = pattern;
        let mut n = string;
        let extmatch = flags & FNM_EXTMATCH != 0;
        let slash_special = no_leading_period(flags);
        loop {
            {
                let mut m = 0usize;
                if !T::WIDE && flags & FNM_CASEFOLD != 0 && !rusty_libc_core::locale::ctype_special() {
                    let lower = |v: u32| if v.wrapping_sub(65) < 26 { v | 32 } else { v };
                    while n.add(m) < string_end {
                        let pc = (*p.add(m)).v();
                        if pc == QM && !extmatch && (m != 0 || !no_leading_period_) && !(flags & FNM_FILE_NAME != 0 && (*n.add(m)).v() == SLASH) {
                            m += 1;
                            continue;
                        }
                        if pc == 0 || (pc < 128 && SPECIAL[pc as usize]) || (pc == SLASH && slash_special) {
                            break;
                        }
                        let nc = (*n.add(m)).v();
                        if pc != nc && (pc >= 128 || nc >= 128 || lower(pc) != lower(nc)) {
                            break;
                        }
                        m += 1;
                    }
                } else if flags & FNM_CASEFOLD == 0 {
                    let qm_ok = !extmatch;
                    let nlp0 = no_leading_period_;
                    let fname = flags & FNM_FILE_NAME != 0;
                    while n.add(m) < string_end {
                        let pc = (*p.add(m)).v();
                        let nc = (*n.add(m)).v();
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
                while n.add(m) < string_end {
                    let praw = *p.add(m);
                    let pc = praw.v();
                    if pc == QM && !extmatch && (m != 0 || !no_leading_period_) && !(flags & FNM_FILE_NAME != 0 && (*n.add(m)).v() == SLASH) {
                        m += 1;
                        continue;
                    }
                    if pc == 0 || (pc < 128 && SPECIAL[pc as usize]) || (pc == SLASH && slash_special) || fold(praw, flags) != fold(*n.add(m), flags) {
                        break;
                    }
                    m += 1;
                }
                }
                if m != 0 {
                    p = p.add(m);
                    n = n.add(m);
                    no_leading_period_ = false;
                }
            }
            let mut c = *p;
            p = p.add(1);
            if c.v() == 0 {
                break;
            }
            let mut new_nlp = false;
            c = fold(c, flags);
            let mut normal = false;
            match c.v() {
                QM => {
                    if extmatch && (*p).v() == b'(' as u32 {
                        let res = ext_match(c.v(), p, n, string_end, no_leading_period_, flags);
                        if res != -1 {
                            return res;
                        }
                    }
                    if n == string_end || ((*n).v() == SLASH && flags & FNM_FILE_NAME != 0) || ((*n).v() == b'.' as u32 && no_leading_period_) {
                        return FNM_NOMATCH;
                    }
                }
                BSL => {
                    if flags & FNM_NOESCAPE == 0 {
                        c = *p;
                        p = p.add(1);
                        if c.v() == 0 {
                            return FNM_NOMATCH;
                        }
                        c = fold(c, flags);
                    }
                    if n == string_end || fold(*n, flags) != c {
                        return FNM_NOMATCH;
                    }
                }
                STAR => {
                    if extmatch && (*p).v() == b'(' as u32 {
                        let res = ext_match(c.v(), p, n, string_end, no_leading_period_, flags);
                        if res != -1 {
                            return res;
                        }
                    } else if !ends.is_null() {
                        (*ends).pattern = p.sub(1);
                        (*ends).string = n;
                        (*ends).no_leading_period = no_leading_period_;
                        return 0;
                    }
                    if n != string_end && (*n).v() == b'.' as u32 && no_leading_period_ {
                        return FNM_NOMATCH;
                    }
                    c = *p;
                    p = p.add(1);
                    while c.v() == QM || c.v() == STAR {
                        if (*p).v() == b'(' as u32 && extmatch {
                            let endp = end_pattern(p);
                            if endp != p {
                                p = endp;
                                c = *p;
                                p = p.add(1);
                                continue;
                            }
                        }
                        if c.v() == QM {
                            if n == string_end || ((*n).v() == SLASH && flags & FNM_FILE_NAME != 0) {
                                return FNM_NOMATCH;
                            }
                            n = n.add(1);
                        }
                        c = *p;
                        p = p.add(1);
                    }
                    if c.v() == 0 {
                        return if flags & FNM_FILE_NAME == 0 || flags & FNM_LEADING_DIR != 0 || memchr(n, k(b'/'), string_end).is_null() { 0 } else { FNM_NOMATCH };
                    }
                    let mut end = Ends { pattern: null(), string: null(), no_leading_period: false };
                    let mut endp = if flags & FNM_FILE_NAME != 0 && c.v() != SLASH { memchr(n, k(b'/'), string_end) } else { null() };
                    if endp.is_null() {
                        endp = string_end;
                    }
                    let mut found = false;
                    if c.v() == LBR || (extmatch && (c.v() == AT || c.v() == PLUS || c.v() == BANG) && (*p).v() == b'(' as u32) {
                        let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
                        p = p.sub(1);
                        let pre = !T::WIDE && c.v() == LBR && (*p.add(1)).v() != b'^' as u32 && byte_order_collation();
                        let neg = pre && (*p.add(1)).v() == BANG;
                        while n < endp {
                            if pre {
                                let mut bp = p.add(1 + neg as usize) as *const u8;
                                let nc = fold(*n, flags);
                                match bracket_fast(&mut bp, nc.v() as u8, (*n).v() as u8, flags) {
                                    Some(Bracket::NotMatched) if !neg => {
                                        n = n.add(1);
                                        no_leading_period_ = false;
                                        continue;
                                    }
                                    Some(Bracket::Matched) if neg => {
                                        n = n.add(1);
                                        no_leading_period_ = false;
                                        continue;
                                    }
                                    _ => {}
                                }
                            }
                            if fct(p, n, string_end, no_leading_period_, flags2, &mut end) == 0 {
                                found = true;
                                break;
                            }
                            n = n.add(1);
                            no_leading_period_ = false;
                        }
                    } else if c.v() == SLASH && flags & FNM_FILE_NAME != 0 {
                        let q = memchr(n, k(b'/'), string_end);
                        n = if q.is_null() { string_end } else { q };
                        if n < string_end && (*n).v() == SLASH {
                            if ends.is_null() {
                                n = n.add(1);
                                no_leading_period_ = flags & FNM_PERIOD != 0;
                                continue;
                            }
                            if fct(p, n.add(1), string_end, flags & FNM_PERIOD != 0, flags, null_mut()) == 0 {
                                return 0;
                            }
                        }
                    } else {
                        let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
                        if c.v() == BSL && flags & FNM_NOESCAPE == 0 {
                            c = *p;
                        }
                        c = fold(c, flags);
                        p = p.sub(1);
                        while n < endp {
                            if flags & FNM_CASEFOLD == 0 {
                                let q = memchr(n, c, endp);
                                if q.is_null() {
                                    break;
                                }
                                if q != n {
                                    n = q;
                                    no_leading_period_ = false;
                                }
                            }
                            if fold(*n, flags) == c && fct(p, n, string_end, no_leading_period_, flags2, &mut end) == 0 {
                                found = true;
                                break;
                            }
                            n = n.add(1);
                            no_leading_period_ = false;
                        }
                    }
                    if found {
                        if end.pattern.is_null() {
                            return 0;
                        }
                        p = end.pattern;
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
                    if (*n).v() == b'.' as u32 && no_leading_period_ {
                        return FNM_NOMATCH;
                    }
                    if (*n).v() == SLASH && flags & FNM_FILE_NAME != 0 {
                        return FNM_NOMATCH;
                    }
                    let not = (*p).v() == BANG || (pc < 0 && (*p).v() == b'^' as u32);
                    if not {
                        p = p.add(1);
                    }
                    let fnc = fold(*n, flags);
                    let mut literal = false;
                    let mut adv = 0usize;
                    let fast = if !T::WIDE && byte_order_collation() {
                        let mut bp = p as *const u8;
                        let r = bracket_fast(&mut bp, fnc.v() as u8, (*n).v() as u8, flags);
                        if r.is_some() {
                            p = bp as P<T>;
                        }
                        r
                    } else {
                        None
                    };
                    match fast.unwrap_or_else(|| bracket_members(&mut p, n, fnc, flags, &mut adv)) {
                        Bracket::Fail => return FNM_NOMATCH,
                        Bracket::Literal => literal = true,
                        Bracket::NotMatched => {
                            if !not {
                                return FNM_NOMATCH;
                            }
                        }
                        Bracket::Matched => match skip_rest(&mut p, flags) {
                            Err(()) => return FNM_NOMATCH,
                            Ok(true) => literal = true,
                            Ok(false) => {
                                if not {
                                    return FNM_NOMATCH;
                                }
                                n = n.add(adv);
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
                    if extmatch && (*p).v() == b'(' as u32 {
                        let res = ext_match(c.v(), p, n, string_end, no_leading_period_, flags);
                        if res != -1 {
                            return res;
                        }
                    }
                    normal = true;
                }
                SLASH => {
                    if no_leading_period(flags) {
                        if n == string_end || c != *n {
                            return FNM_NOMATCH;
                        }
                        new_nlp = true;
                    } else {
                        normal = true;
                    }
                }
                _ => normal = true,
            }
            if normal && (n == string_end || c != fold(*n, flags)) {
                return FNM_NOMATCH;
            }
            no_leading_period_ = new_nlp;
            n = n.add(1);
        }
        if n == string_end {
            return 0;
        }
        if flags & FNM_LEADING_DIR != 0 && (*n).v() == SLASH {
            return 0;
        }
        FNM_NOMATCH
    }
}

unsafe fn to_wide(s: *const u8, stack: *mut u32, cap: usize) -> Option<(*mut u32, usize, bool)> {
    unsafe {
        use rusty_libc_wchar::mbstate_t;
        use rusty_libc_wchar::mbyte::mbsrtowcs;
        let mut ps = mbstate_t::default();
        let mut src = s as *const c_char;
        let r = mbsrtowcs(stack.cast(), &mut src, cap, &mut ps);
        if r == usize::MAX {
            return None;
        }
        if src.is_null() {
            return Some((stack, r, false));
        }
        let mut ps = mbstate_t::default();
        let mut src = s as *const c_char;
        let n = mbsrtowcs(null_mut(), &mut src, 0, &mut ps);
        if n == usize::MAX {
            return None;
        }
        let buf = rusty_libc_malloc::malloc((n + 1) * 4) as *mut u32;
        if buf.is_null() {
            return None;
        }
        let mut ps = mbstate_t::default();
        let mut src = s as *const c_char;
        mbsrtowcs(buf.cast(), &mut src, n + 1, &mut ps);
        Some((buf, n, true))
    }
}

unsafe fn is_ascii_c(p: *const c_char) -> bool {
    unsafe {
        let mut q = p as *const u8;
        while *q != 0 {
            if *q >= 0x80 {
                return false;
            }
            q = q.add(1);
        }
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int {
    unsafe {
        let s = string as P<u8>;
        let slen = cstrlen(s);
        if rusty_libc_wchar::mbyte::mb_cur_max() != 1 && !(flags & FNM_CASEFOLD == 0 && core::slice::from_raw_parts(s, slen).is_ascii() && is_ascii_c(pattern)) && wide_match(pattern, s, flags) {
            return 0;
        }
        if flags & !(FNM_NOESCAPE | FNM_CASEFOLD) == 0
            && let Some(r) = simple_match(pattern as P<u8>, s, slen, flags & FNM_CASEFOLD != 0)
        {
            return r;
        }
        fct::<u8>(pattern as P<u8>, s, s.add(slen), flags & FNM_PERIOD != 0, flags, null_mut())
    }
}

#[inline]
unsafe fn simple_match(pattern: P<u8>, s: P<u8>, slen: usize, casefold: bool) -> Option<c_int> {
    unsafe {
        if casefold && rusty_libc_core::locale::ctype_special() {
            return None;
        }
        let mut p = pattern;
        let star = *p == b'*';
        if star {
            p = p.add(1);
        }
        let mut l = 0usize;
        let mut trailing = false;
        loop {
            let c = *p.add(l);
            if c == 0 {
                break;
            }
            if c == b'*' && !star && *p.add(l + 1) == 0 {
                trailing = true;
                break;
            }
            if c >= 128 || c == b'?' || c == b'*' || c == b'[' || c == b'\\' {
                return None;
            }
            l += 1;
        }
        let start = if trailing {
            if slen < l {
                return Some(FNM_NOMATCH);
            }
            0
        } else if star {
            if slen < l {
                return Some(FNM_NOMATCH);
            }
            slen - l
        } else {
            if slen != l {
                return Some(FNM_NOMATCH);
            }
            0
        };
        let t = s.add(start);
        let mut i = 0usize;
        if !casefold {
            while i + 8 <= l {
                if core::ptr::read_unaligned(p.add(i) as *const u64) != core::ptr::read_unaligned(t.add(i) as *const u64) {
                    return Some(FNM_NOMATCH);
                }
                i += 8;
            }
        }
        while i < l {
            let (a, b) = (*p.add(i), *t.add(i));
            if a != b && !(casefold && b < 128 && a.eq_ignore_ascii_case(&b)) {
                return Some(FNM_NOMATCH);
            }
            i += 1;
        }
        Some(0)
    }
}

#[inline(never)]
unsafe fn wide_match(pattern: *const c_char, s: P<u8>, flags: c_int) -> bool {
    unsafe {
        let mut pstack = core::mem::MaybeUninit::<[u32; 256]>::uninit();
        let mut sstack = core::mem::MaybeUninit::<[u32; 256]>::uninit();
        let mut r = FNM_NOMATCH;
        if let Some((wp, _, pheap)) = to_wide(pattern as *const u8, pstack.as_mut_ptr().cast(), 256) {
            if let Some((ws, wn, sheap)) = to_wide(s, sstack.as_mut_ptr().cast(), 256) {
                r = fct::<u32>(wp, ws, ws.add(wn), flags & FNM_PERIOD != 0, flags, null_mut());
                if sheap {
                    rusty_libc_malloc::free(ws.cast());
                }
            }
            if pheap {
                rusty_libc_malloc::free(wp.cast());
            }
        }
        r == 0
    }
}

pub fn matches(pattern: &core::ffi::CStr, string: &core::ffi::CStr, flags: c_int) -> bool {
    unsafe { fnmatch(pattern.as_ptr(), string.as_ptr(), flags) == 0 }
}
