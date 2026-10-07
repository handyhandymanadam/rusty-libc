use crate::charset::{self, Mb};
use crate::vec::V;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug)]
pub struct Seq {
    pub r: [(u8, u8); 6],
    pub n: u8,
}

fn utf8_len(wc: u32) -> usize {
    match wc {
        0..=0x7f => 1,
        0x80..=0x7ff => 2,
        0x800..=0xffff => 3,
        _ => 4,
    }
}

fn utf8_encode(wc: u32, out: &mut [u8; 4]) -> usize {
    match utf8_len(wc) {
        1 => {
            out[0] = wc as u8;
            1
        }
        2 => {
            out[0] = 0xc0 | (wc >> 6) as u8;
            out[1] = 0x80 | (wc & 0x3f) as u8;
            2
        }
        3 => {
            out[0] = 0xe0 | (wc >> 12) as u8;
            out[1] = 0x80 | ((wc >> 6) & 0x3f) as u8;
            out[2] = 0x80 | (wc & 0x3f) as u8;
            3
        }
        _ => {
            out[0] = 0xf0 | (wc >> 18) as u8;
            out[1] = 0x80 | ((wc >> 12) & 0x3f) as u8;
            out[2] = 0x80 | ((wc >> 6) & 0x3f) as u8;
            out[3] = 0x80 | (wc & 0x3f) as u8;
            4
        }
    }
}

pub fn utf8_ranges(lo: u32, hi: u32, out: &mut V<Seq>) {
    let mut stack: V<(u32, u32)> = V::new();
    stack.push((lo, hi));
    while let Some((lo, hi)) = stack.pop() {
        if lo > hi {
            continue;
        }
        if lo <= 0xdfff && hi >= 0xd800 {
            if hi > 0xdfff {
                stack.push((0xe000, hi));
            }
            if lo < 0xd800 {
                stack.push((lo, 0xd7ff));
            }
            continue;
        }
        let mut split = false;
        for &b in &[0x7fu32, 0x7ff, 0xffff] {
            if lo <= b && b < hi {
                stack.push((b + 1, hi));
                stack.push((lo, b));
                split = true;
                break;
            }
        }
        if split {
            continue;
        }
        if hi <= 0x7f {
            out.push(Seq { r: [(lo as u8, hi as u8), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0)], n: 1 });
            continue;
        }
        let mut again = false;
        for i in 1..4u32 {
            let m: u32 = (1 << (6 * i)) - 1;
            if (lo & !m) != (hi & !m) {
                if lo & m != 0 {
                    stack.push(((lo | m) + 1, hi));
                    stack.push((lo, lo | m));
                    again = true;
                    break;
                }
                if hi & m != m {
                    stack.push((hi & !m, hi));
                    stack.push((lo, (hi & !m) - 1));
                    again = true;
                    break;
                }
            }
        }
        if again {
            continue;
        }
        let (mut a, mut b) = ([0u8; 4], [0u8; 4]);
        let n = utf8_encode(lo, &mut a);
        utf8_encode(hi, &mut b);
        let mut s = Seq { r: [(0, 0); 6], n: n as u8 };
        for k in 0..n {
            s.r[k] = (a[k], b[k]);
        }
        out.push(s);
    }
}

#[derive(Clone, Copy)]
pub struct Ch {
    pub b: [u8; 4],
    pub n: u8,
    pub wc: u32,
}

struct Cache {
    key: usize,
    ptr: *mut Ch,
    len: usize,
}

static LOCK: AtomicBool = AtomicBool::new(false);
static mut CACHE: Cache = Cache { key: 0, ptr: core::ptr::null_mut(), len: 0 };

pub fn other_chars() -> &'static [Ch] {
    let key = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) as usize;
    while LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let c = unsafe { &mut *core::ptr::addr_of_mut!(CACHE) };
    if c.key != key || c.ptr.is_null() {
        let mut v: V<Ch> = V::new();
        rusty_libc_wchar::mbyte::each_other_char(&mut |bytes, wc| {
            let mut b = [0u8; 4];
            b[..bytes.len()].copy_from_slice(bytes);
            v.push(Ch { b, n: bytes.len() as u8, wc });
        });
        c.ptr = core::ptr::null_mut();
        c.len = 0;
        if !v.oom && !v.is_empty() {
            let p = unsafe { rusty_libc_malloc::malloc(v.len() * core::mem::size_of::<Ch>()) } as *mut Ch;
            if !p.is_null() {
                unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), p, v.len()) };
                c.ptr = p;
                c.len = v.len();
                c.key = key;
            }
        }
    }
    let r: &'static [Ch] = if c.ptr.is_null() { &[] } else { unsafe { core::slice::from_raw_parts(c.ptr, c.len) } };
    LOCK.store(false, Ordering::Release);
    r
}

pub fn collect(k: Mb, singles: bool, limit: u32, pred: &mut dyn FnMut(u32, usize) -> bool, out: &mut V<Seq>) {
    match k {
        Mb::Utf8 => {
            let mut run: Option<u32> = None;
            let mut last = 0u32;
            let start = if singles { 0 } else { 0x80 };
            let mut wc = start;
            while wc <= limit {
                let ok = !(0xd800..=0xdfff).contains(&wc) && pred(wc, utf8_len(wc));
                if ok {
                    if run.is_none() {
                        run = Some(wc);
                    }
                    last = wc;
                } else if let Some(s) = run.take() {
                    utf8_ranges(s, last, out);
                }
                wc += 1;
            }
            if let Some(s) = run {
                utf8_ranges(s, last, out);
            }
        }
        _ => {
            for c in other_chars() {
                if (c.n > 1 || singles) && pred(c.wc, c.n as usize) {
                    let n = c.n as usize;
                    if let Some(last) = out.last_mut()
                        && last.n == c.n
                        && last.r[..n - 1].iter().zip(c.b.iter()).all(|(r, &b)| *r == (b, b))
                        && last.r[n - 1].1.checked_add(1) == Some(c.b[n - 1])
                    {
                        last.r[n - 1].1 = c.b[n - 1];
                        continue;
                    }
                    let mut s = Seq { r: [(0, 0); 6], n: c.n };
                    for i in 0..n {
                        s.r[i] = (c.b[i], c.b[i]);
                    }
                    out.push(s);
                }
            }
        }
    }
}

pub fn seq_of(k: Mb, wc: u32) -> Option<Seq> {
    let mut b = [0u8; 6];
    let n = charset::encode(k, wc, &mut b)?;
    if n > 4 {
        return None;
    }
    let mut s = Seq { r: [(0, 0); 6], n: n as u8 };
    for i in 0..n {
        s.r[i] = (b[i], b[i]);
    }
    Some(s)
}

pub type Set = [u64; 4];

fn set_range(s: &mut Set, lo: u8, hi: u8) {
    for b in lo as u32..=hi as u32 {
        s[(b >> 6) as usize] |= 1u64 << (b & 63);
    }
}

#[derive(Clone, Copy)]
struct Edge {
    lo: u8,
    hi: u8,
    child: u32,
    next: u32,
}

pub struct Trie {
    head: V<u32>,
    edges: V<Edge>,
}

const NIL: u32 = u32::MAX;

impl Trie {
    pub fn new() -> Trie {
        let mut t = Trie { head: V::new(), edges: V::new() };
        t.head.push(NIL);
        t
    }

    pub fn insert(&mut self, s: &Seq) {
        let mut cur = 0u32;
        for &(lo, hi) in s.r.iter().take(s.n as usize) {
            let mut e = self.head[cur as usize];
            let mut found = NIL;
            while e != NIL {
                let ed = self.edges[e as usize];
                if ed.lo == lo && ed.hi == hi {
                    found = e;
                    break;
                }
                e = ed.next;
            }
            if found != NIL {
                cur = self.edges[found as usize].child;
            } else {
                let child = self.head.len() as u32;
                self.head.push(NIL);
                let id = self.edges.len() as u32;
                self.edges.push(Edge { lo, hi, child, next: self.head[cur as usize] });
                self.head[cur as usize] = id;
                cur = child;
            }
        }
    }

    pub fn oom(&self) -> bool {
        self.head.oom || self.edges.oom
    }

    pub fn is_empty(&self) -> bool {
        self.head[0] == NIL
    }

    pub fn canon(&self) -> Canon {
        let n = self.head.len();
        let mut id_of: V<u32> = V::from_elem(0, n);
        let mut c = Canon { groups: V::new(), start: V::new(), root: 0, oom: false };
        c.start.push(0);
        c.groups.push((0, [0; 4]));
        let mut i = n;
        while i > 0 {
            i -= 1;
            let mut gs: V<(u32, Set)> = V::new();
            let mut e = self.head[i];
            while e != NIL {
                let ed = self.edges[e as usize];
                let cid = id_of[ed.child as usize];
                let mut found = None;
                for (k, g) in gs.iter().enumerate() {
                    if g.0 == cid {
                        found = Some(k);
                        break;
                    }
                }
                match found {
                    Some(k) => set_range(&mut gs[k].1, ed.lo, ed.hi),
                    None => {
                        let mut s = [0u64; 4];
                        set_range(&mut s, ed.lo, ed.hi);
                        gs.push((cid, s));
                    }
                }
                e = ed.next;
            }
            if gs.is_empty() {
                id_of[i] = 0;
                continue;
            }
            let len = gs.len();
            for a in 1..len {
                let mut b = a;
                while b > 0 && gs[b - 1].0 > gs[b].0 {
                    gs.swap(b - 1, b);
                    b -= 1;
                }
            }
            let mut same = 0u32;
            'scan: for cand in 1..c.start.len() {
                let (s0, s1) = c.range(cand as u32);
                if s1 - s0 != len {
                    continue;
                }
                for k in 0..len {
                    if c.groups[s0 + k] != gs[k] {
                        continue 'scan;
                    }
                }
                same = cand as u32;
                break;
            }
            if same != 0 {
                id_of[i] = same;
            } else {
                let nid = c.start.len() as u32;
                c.start.push(c.groups.len());
                for g in gs.iter() {
                    c.groups.push(*g);
                }
                id_of[i] = nid;
            }
            let _ = &mut id_of;
        }
        c.root = id_of[0];
        c.oom = id_of.oom || c.groups.oom || c.start.oom;
        c
    }
}

impl Default for Trie {
    fn default() -> Trie {
        Trie::new()
    }
}

pub struct Canon {
    groups: V<(u32, Set)>,
    start: V<usize>,
    pub root: u32,
    pub oom: bool,
}

impl Canon {
    pub fn none() -> Canon {
        Canon { groups: V::new(), start: V::new(), root: u32::MAX, oom: false }
    }

    fn range(&self, id: u32) -> (usize, usize) {
        let s = self.start[id as usize];
        let e = if (id as usize + 1) < self.start.len() { self.start[id as usize + 1] } else { self.groups.len() };
        (s, e)
    }

    pub fn groups(&self, id: u32) -> &[(u32, Set)] {
        if id == 0 {
            return &[];
        }
        let (s, e) = self.range(id);
        &self.groups[s..e]
    }
}

struct Entry {
    key: V<u8>,
    canon: Canon,
}

static CACHE_LOCK: AtomicBool = AtomicBool::new(false);
static mut ENTRIES: V<Entry> = V::new();
static mut NEXT_SLOT: usize = 0;
const CACHE_SLOTS: usize = 64;

pub fn canon_with<R>(key: &[u8], f: impl FnOnce(&Canon) -> R) -> Option<R> {
    while CACHE_LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let entries = unsafe { &*core::ptr::addr_of!(ENTRIES) };
    let mut r = None;
    for e in entries.iter() {
        if e.key.len() == key.len() && e.key[..] == *key {
            r = Some(f(&e.canon));
            break;
        }
    }
    CACHE_LOCK.store(false, Ordering::Release);
    r
}

pub fn canon_put(key: &[u8], canon: Canon) {
    if canon.oom {
        return;
    }
    let mut k: V<u8> = V::new();
    k.extend_from_slice(key);
    if k.oom {
        return;
    }
    while CACHE_LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    unsafe {
        let entries = &mut *core::ptr::addr_of_mut!(ENTRIES);
        let next = &mut *core::ptr::addr_of_mut!(NEXT_SLOT);
        if entries.len() < CACHE_SLOTS {
            entries.push(Entry { key: k, canon });
        } else {
            entries[*next % CACHE_SLOTS] = Entry { key: k, canon };
            *next += 1;
        }
    }
    CACHE_LOCK.store(false, Ordering::Release);
}

pub type Ranges = V<(u32, u32)>;

pub const UTF8_DOMAIN: [(u32, u32); 2] = [(0x80, 0xd7ff), (0xe000, 0x10ffff)];

pub fn normalize(r: &mut Ranges) {
    r.sort_unstable();
    let mut w = 0usize;
    for i in 0..r.len() {
        let (lo, hi) = r[i];
        if w > 0 && lo <= r[w - 1].1.saturating_add(1) {
            if hi > r[w - 1].1 {
                r[w - 1].1 = hi;
            }
        } else {
            r[w] = (lo, hi);
            w += 1;
        }
    }
    r.truncate(w);
}

pub fn clip(r: &Ranges, dom: &[(u32, u32)]) -> Ranges {
    let mut out: Ranges = V::new();
    for &(lo, hi) in r.iter() {
        for &(dlo, dhi) in dom {
            let (a, b) = (lo.max(dlo), hi.min(dhi));
            if a <= b {
                out.push((a, b));
            }
        }
    }
    normalize(&mut out);
    out
}

pub fn complement(r: &Ranges, dom: &[(u32, u32)]) -> Ranges {
    let mut out: Ranges = V::new();
    for &(dlo, dhi) in dom {
        let mut next = dlo;
        for &(lo, hi) in r.iter() {
            if hi < next || lo > dhi {
                continue;
            }
            if lo > next {
                out.push((next, lo - 1));
            }
            next = hi.saturating_add(1);
            if next > dhi {
                break;
            }
        }
        if next <= dhi && next >= dlo {
            out.push((next, dhi));
        }
    }
    out
}

pub fn contains(r: &Ranges, c: u32) -> bool {
    let (mut lo, mut hi) = (0usize, r.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (a, b) = r[mid];
        if c < a {
            hi = mid;
        } else if c > b {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    false
}

pub fn utf8_seqs(r: &Ranges, out: &mut V<Seq>) {
    for &(lo, hi) in r.iter() {
        utf8_ranges(lo, hi, out);
    }
}
