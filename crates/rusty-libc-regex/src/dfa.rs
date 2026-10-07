#![allow(clippy::needless_range_loop, clippy::collapsible_if)]
use crate::consts::*;
use crate::exec::Env;
use crate::nfa::*;
use crate::vec::V;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const PURE: u32 = 1 << 31;
const ACC: u32 = 1 << 30;
const UNKNOWN: u32 = u32::MAX;
const MAX_STATES: usize = 1200;

#[inline]
fn state_cap() -> usize {
    {
        MAX_STATES
    }
}

const MAX_NODES: usize = 3000;
pub const MIN_TEXT: usize = 64;
const SHORT_CALLS: u32 = 8;

pub enum Pre {
    NoMatch,
    Window { q: usize, p1: usize },
    Unavailable,
}

pub enum Loc {
    NoMatch,
    Found(usize, usize),
    Window(usize),
    Unavailable,
}

pub struct Dfa {
    lock: AtomicBool,
    short_calls: AtomicU32,
    inner: UnsafeCell<Both>,
}

struct Both {
    fwd: Inner,
    anch: Inner,
}

unsafe impl Sync for Dfa {}
unsafe impl Send for Dfa {}

impl Dfa {
    pub const fn new() -> Dfa {
        Dfa { lock: AtomicBool::new(false), short_calls: AtomicU32::new(0), inner: UnsafeCell::new(Both { fwd: Inner::new(false), anch: Inner::new(true) }) }
    }

    pub fn locate(&self, env: &Env, start0: usize, need_longest: bool) -> Loc {
        if env.nfa.nbackref != 0 || env.nfa.nodes.len() > MAX_NODES || env.stop != env.text.len() {
            return Loc::Unavailable;
        }
        if env.nfa.mb != crate::charset::Mb::None && (env.nfa.word_ctx || !env.text[start0.min(env.text.len())..].is_ascii()) {
            return Loc::Unavailable;
        }
        if env.text.len() - start0 < MIN_TEXT && self.short_calls.fetch_add(1, Ordering::Relaxed) < SHORT_CALLS {
            return Loc::Unavailable;
        }
        if self.lock.swap(true, Ordering::Acquire) {
            return Loc::Unavailable;
        }
        let both = unsafe { &mut *self.inner.get() };
        let r = match both.fwd.scan(env, start0) {
            Pre::NoMatch => Loc::NoMatch,
            Pre::Unavailable => Loc::Unavailable,
            Pre::Window { q, p1 } => {
                if !need_longest {
                    Loc::Found(q, p1)
                } else {
                    both.anch.find(env, q, p1)
                }
            }
        };
        self.lock.store(false, Ordering::Release);
        r
    }
}

impl Default for Dfa {
    fn default() -> Dfa {
        Dfa::new()
    }
}

struct Inner {
    anchored: bool,
    prepared: bool,
    disabled: bool,
    resets: u32,
    xlat: [u8; 256],
    xlat_fixed: bool,
    newline_anchor: bool,
    raw_cls: [u8; 256],
    ncls: usize,
    rep: [u8; 256],
    cls_trans: [u8; 256],
    cls_real: [u8; 256],
    first_raw: [u8; 256],
    nib: bool,
    nib_lo: [u8; 16],
    nib_hi: [u8; 16],
    init_has_end: bool,
    arena: V<u32>,
    st_off: V<u32>,
    st_len: V<u32>,
    st_acc: V<u8>,
    trans: V<u32>,
    table: V<u32>,
    init_ids: [(u8, u32); 8],
    n_init: usize,
    pure_ids: [u32; 3],
    scratch: V<u32>,
    mark: V<u32>,
    generation: u32,
}

const NOID: u32 = u32::MAX;

impl Inner {
    const fn new(anchored: bool) -> Inner {
        Inner {
            anchored,
            prepared: false,
            disabled: false,
            resets: 0,
            xlat: [0; 256],
            xlat_fixed: false,
            newline_anchor: false,
            raw_cls: [0; 256],
            ncls: 0,
            rep: [0; 256],
            cls_trans: [0; 256],
            cls_real: [0; 256],
            first_raw: [0; 256],
            nib: false,
            nib_lo: [0; 16],
            nib_hi: [0; 16],
            init_has_end: false,
            arena: V::new(),
            st_off: V::new(),
            st_len: V::new(),
            st_acc: V::new(),
            trans: V::new(),
            table: V::new(),
            init_ids: [(0, 0); 8],
            n_init: 0,
            pure_ids: [NOID; 3],
            scratch: V::new(),
            mark: V::new(),
            generation: 0,
        }
    }

    fn reset_states(&mut self) {
        self.arena.clear();
        self.st_off.clear();
        self.st_len.clear();
        self.st_acc.clear();
        self.trans.clear();
        self.table.clear();
        self.n_init = 0;
        self.pure_ids = [NOID; 3];
    }

    fn prepare(&mut self, env: &Env) -> bool {
        if self.disabled {
            return false;
        }
        if self.prepared && self.newline_anchor == env.newline_anchor && ((env.xlat_fixed && self.xlat_fixed) || same_table(&self.xlat, env.xlat)) {
            return true;
        }
        let nfa = env.nfa;
        self.reset_states();
        self.prepared = false;
        let mut cls = [0u16; 256];
        let mut ncls = 1usize;
        let refine = |bit: &dyn Fn(usize) -> bool, cls: &mut [u16; 256], ncls: &mut usize| {
            let mut remap = [u16::MAX; 512];
            let mut next = 0u16;
            for b in 0..256 {
                let key = cls[b] as usize * 2 + usize::from(bit(b));
                if remap[key] == u16::MAX {
                    remap[key] = next;
                    next += 1;
                }
                cls[b] = remap[key];
            }
            *ncls = next as usize;
        };
        refine(&|b| crate::charset::is_word(b as u8), &mut cls, &mut ncls);
        refine(&|b| b == usize::from(b'\n'), &mut cls, &mut ncls);
        if nfa.syntax & RE_DOT_NOT_NULL != 0 {
            refine(&|b| b == 0, &mut cls, &mut ncls);
        }
        for nd in nfa.nodes.iter() {
            match nd.kind {
                K_CHAR => {
                    let c = nd.c as usize;
                    refine(&|b| b == c, &mut cls, &mut ncls);
                }
                K_SET => {
                    let set = &nfa.sets[nd.arg as usize];
                    refine(&|b| crate::parse::set_has(set, b as u8), &mut cls, &mut ncls);
                }
                _ => {}
            }
            if ncls >= 256 {
                break;
            }
        }
        self.ncls = ncls;
        let mut seen = [false; 256];
        for b in 0..256usize {
            let c = cls[b] as usize;
            if !seen[c] {
                seen[c] = true;
                self.rep[c] = b as u8;
                self.cls_trans[c] = trans_ctx(b as u8);
                self.cls_real[c] = if crate::charset::is_word(b as u8) {
                    CTX_WORD
                } else if b == usize::from(b'\n') && env.newline_anchor {
                    CTX_NEWLINE
                } else {
                    0
                };
            }
        }
        self.xlat = *env.xlat;
        self.xlat_fixed = env.xlat_fixed;
        self.newline_anchor = env.newline_anchor;
        for raw in 0..256usize {
            self.raw_cls[raw] = cls[env.xlat[raw] as usize] as u8;
        }
        self.first_raw = [0; 256];
        self.init_has_end = false;
        for &n in nfa.init_nodes.iter() {
            let nd = &nfa.nodes[n as usize];
            match nd.kind {
                K_END => self.init_has_end = true,
                K_CHAR | K_SET | K_ANY => {
                    for raw in 0..256usize {
                        if env.accept_base(nd, env.xlat[raw]) {
                            self.first_raw[raw] = 1;
                        }
                    }
                }
                _ => {}
            }
        }
        match nibble_tables(&self.first_raw) {
            Some((lo, hi)) => {
                self.nib = true;
                self.nib_lo = lo;
                self.nib_hi = hi;
            }
            None => self.nib = false,
        }
        self.mark = V::from_elem(0, nfa.nodes.len());
        self.generation = 0;
        if self.mark.oom {
            self.mark = V::new();
            return false;
        }
        self.prepared = true;
        true
    }

    #[inline]
    fn skip(&self, text: &[u8], from: usize) -> usize {
        #[cfg(target_arch = "x86_64")]
        if self.nib && text.len() - from >= 32 && has_avx2() {
            return unsafe { skip_avx2(text, from, &self.nib_lo, &self.nib_hi) };
        }
        let fr = &self.first_raw;
        let mut i = from;
        while i < text.len() {
            if unsafe { *fr.get_unchecked(*text.get_unchecked(i) as usize) } != 0 {
                break;
            }
            i += 1;
        }
        i
    }

    fn state_nodes(&self, s: u32) -> (usize, usize) {
        let o = self.st_off[s as usize] as usize;
        (o, o + self.st_len[s as usize] as usize)
    }

    fn add(&mut self, nfa: &Nfa, x: u32, ctx: u8) {
        if self.mark[x as usize] == self.generation {
            return;
        }
        let nd = &nfa.nodes[x as usize];
        if nd.constraint != 0 && prev_bad(nd.constraint, ctx) {
            return;
        }
        self.mark[x as usize] = self.generation;
        if matches!(nd.kind, K_CHAR | K_SET | K_ANY | K_END) {
            self.scratch.push(x);
        }
    }

    fn intern(&mut self, nfa: &Nfa) -> Option<u32> {
        if self.scratch.oom {
            return None;
        }
        self.scratch.sort_unstable();
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &n in self.scratch.iter() {
            h = (h ^ u64::from(n)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        if self.table.len() < 64 || self.st_off.len() * 2 >= self.table.len() {
            let ncap = (self.table.len() * 2).max(256);
            self.table = V::from_elem(NOID, ncap);
            if self.table.oom {
                self.table = V::new();
                return None;
            }
            for id in 0..self.st_off.len() {
                let (a, b) = self.state_nodes(id as u32);
                let mut hh: u64 = 0xcbf2_9ce4_8422_2325;
                for &n in &self.arena[a..b] {
                    hh = (hh ^ u64::from(n)).wrapping_mul(0x0000_0100_0000_01b3);
                }
                let mut i = hh as usize & (ncap - 1);
                while self.table[i] != NOID {
                    i = (i + 1) & (ncap - 1);
                }
                self.table[i] = id as u32;
            }
        }
        let cap = self.table.len();
        let mut i = h as usize & (cap - 1);
        loop {
            let id = self.table[i];
            if id == NOID {
                break;
            }
            let (a, b) = self.state_nodes(id);
            if self.arena[a..b] == self.scratch[..] {
                return Some(id);
            }
            i = (i + 1) & (cap - 1);
        }
        if self.st_off.len() >= state_cap() {
            return None;
        }
        let mut acc = 0u8;
        for &n in self.scratch.iter() {
            let nd = &nfa.nodes[n as usize];
            if nd.kind == K_END {
                for (bit, ctx) in [(0u8, 0u8), (1, CTX_WORD), (2, CTX_NEWLINE), (3, CTX_ENDBUF | CTX_NEWLINE), (4, CTX_ENDBUF)] {
                    if nd.constraint == 0 || !next_bad(nd.constraint, ctx) {
                        acc |= 1 << bit;
                    }
                }
            }
        }
        let id = self.st_off.len() as u32;
        self.st_off.push(self.arena.len() as u32);
        self.st_len.push(self.scratch.len() as u32);
        self.st_acc.push(acc);
        for k in 0..self.scratch.len() {
            let n = self.scratch[k];
            self.arena.push(n);
        }
        let new_len = self.trans.len() + self.ncls + 1;
        self.trans.resize(new_len, UNKNOWN);
        self.trans[new_len - 1] = u32::from(acc);
        if self.arena.oom || self.st_off.oom || self.st_len.oom || self.st_acc.oom || self.trans.oom {
            return None;
        }
        self.table[i] = id;
        Some(id)
    }

    fn init_state(&mut self, nfa: &Nfa, tip: u8) -> Option<u32> {
        for k in 0..self.n_init {
            if self.init_ids[k].0 == tip {
                return Some(self.init_ids[k].1);
            }
        }
        self.scratch.clear();
        self.generation += 1;
        for &x in nfa.init_nodes.iter() {
            self.add(nfa, x, tip);
        }
        let id = self.intern(nfa)?;
        if self.n_init < self.init_ids.len() {
            self.init_ids[self.n_init] = (tip, id);
            self.n_init += 1;
        }
        Some(id)
    }

    fn pure_state(&mut self, nfa: &Nfa, rc: u8) -> Option<u32> {
        let k = rc as usize;
        if self.pure_ids[k] != NOID {
            return Some(self.pure_ids[k]);
        }
        self.scratch.clear();
        self.generation += 1;
        for &x in nfa.init_nodes.iter() {
            self.add(nfa, x, rc);
        }
        let id = self.intern(nfa)?;
        self.pure_ids[k] = id;
        Some(id)
    }

    fn step(&mut self, env: &Env, s_off: u32, c: usize) -> Option<u32> {
        let nfa = env.nfa;
        let s = s_off / (self.ncls as u32 + 1);
        let b = self.rep[c];
        let pc = self.cls_trans[c];
        self.scratch.clear();
        self.generation += 1;
        let (lo, hi) = self.state_nodes(s);
        for k in lo..hi {
            let n = self.arena[k];
            let nd = &nfa.nodes[n as usize];
            if matches!(nd.kind, K_CHAR | K_SET | K_ANY) && env.consume_dfa(nd, b) {
                for &x in nfa.eclosure(nd.next) {
                    self.add(nfa, x, pc);
                }
            }
        }
        let pure = self.scratch.is_empty();
        if !self.anchored {
            let rc = self.cls_real[c];
            for &x in nfa.init_nodes.iter() {
                self.add(nfa, x, rc);
            }
        }
        let id = self.intern(nfa)?;
        let mut t = id * (self.ncls as u32 + 1);
        if pure {
            t |= PURE;
        }
        if self.st_acc[id as usize] != 0 {
            t |= ACC;
        }
        self.trans[(s_off as usize) + c] = t;
        Some(t)
    }

    fn scan(&mut self, env: &Env, start0: usize) -> Pre {
        if !self.prepare(env) {
            return Pre::Unavailable;
        }
        let nfa = env.nfa;
        let text = env.text;
        let len = text.len();
        let ncls = self.ncls as u32;
        let stride = ncls + 1;
        let Some(init) = self.init_state(nfa, env.tip_ctx(start0)) else {
            return self.give_up();
        };
        let mut off = init * stride;
        let mut p = start0;
        let mut q = start0;
        let mut pure_now = true;
        let mut check = true;
        loop {
            if pure_now && !self.init_has_end {
                let i = self.skip(text, p);
                if i > p {
                    let rc = self.cls_real[self.raw_cls[text[i - 1] as usize] as usize];
                    let Some(ns) = self.pure_state(nfa, rc) else {
                        return self.give_up();
                    };
                    off = ns * stride;
                    p = i;
                    q = i;
                }
            }
            if check {
                let acc = self.trans[(off + ncls) as usize] as u8;
                if acc != 0 {
                    let bit = if p == len {
                        if env.not_eol { 1 << 4 } else { 1 << 3 }
                    } else {
                        1u8 << self.cls_real[self.raw_cls[text[p] as usize] as usize]
                    };
                    if acc & bit != 0 {
                        return Pre::Window { q, p1: p };
                    }
                }
            }
            loop {
                if p == len {
                    return Pre::NoMatch;
                }
                let c = self.raw_cls[text[p] as usize] as usize;
                let t = self.trans[off as usize + c];
                if t & (PURE | ACC) == 0 {
                    off = t;
                    p += 1;
                    continue;
                }
                let t = if t == UNKNOWN {
                    match self.step(env, off, c) {
                        Some(x) => x,
                        None => return self.give_up(),
                    }
                } else {
                    t
                };
                pure_now = t & PURE != 0;
                if pure_now {
                    q = p + 1;
                }
                check = t & ACC != 0;
                off = t & !(PURE | ACC);
                p += 1;
                break;
            }
        }
    }

    fn find(&mut self, env: &Env, q: usize, p1: usize) -> Loc {
        if !self.prepare(env) {
            return Loc::Window(q);
        }
        let nfa = env.nfa;
        let text = env.text;
        let len = text.len();
        let ncls = self.ncls as u32;
        let stride = ncls + 1;
        let mut budget: u64 = 8 * (len - q) as u64 + 2048;
        let mut s = q;
        while s <= p1 {
            if env.start_ok(s) {
                let Some(init) = self.init_state(nfa, env.tip_ctx(s)) else {
                    self.give_up();
                    return Loc::Window(q);
                };
                let mut off = init * stride;
                let mut p = s;
                let mut best: Option<usize> = None;
                let mut check = true;
                'run: loop {
                    if check {
                        let acc = self.trans[(off + ncls) as usize] as u8;
                        if acc != 0 {
                            let bit = if p == len {
                                if env.not_eol { 1 << 4 } else { 1 << 3 }
                            } else {
                                1u8 << self.cls_real[self.raw_cls[text[p] as usize] as usize]
                            };
                            if acc & bit != 0 {
                                best = Some(p);
                            }
                        }
                    }
                    loop {
                        if p == len {
                            break 'run;
                        }
                        let c = self.raw_cls[text[p] as usize] as usize;
                        let t = self.trans[off as usize + c];
                        if t & (PURE | ACC) == 0 {
                            off = t;
                            p += 1;
                            continue;
                        }
                        let t = if t == UNKNOWN {
                            match self.step(env, off, c) {
                                Some(x) => x,
                                None => {
                                    self.give_up();
                                    return Loc::Window(q);
                                }
                            }
                        } else {
                            t
                        };
                        if t & PURE != 0 {
                            p += 1;
                            break 'run;
                        }
                        check = t & ACC != 0;
                        off = t & !(PURE | ACC);
                        p += 1;
                        break;
                    }
                }
                if let Some(e) = best {
                    return Loc::Found(s, e);
                }
                let spent = (p - s) as u64 + 1;
                if spent > budget {
                    return Loc::Window(q);
                }
                budget -= spent;
            }
            s += 1;
        }
        Loc::Window(q)
    }

    fn give_up(&mut self) -> Pre {
        self.reset_states();
        self.scratch = V::new();
        self.resets += 1;
        if self.resets > 6 {
            self.disabled = true;
        }
        Pre::Unavailable
    }
}

#[inline]
fn same_table(a: &[u8; 256], b: &[u8; 256]) -> bool {
    unsafe {
        let (pa, pb) = (a.as_ptr() as *const u64, b.as_ptr() as *const u64);
        let mut diff = 0u64;
        for i in 0..32 {
            diff |= pa.add(i).read_unaligned() ^ pb.add(i).read_unaligned();
        }
        diff == 0
    }
}

fn trans_ctx(b: u8) -> u8 {
    if crate::charset::is_word(b) {
        CTX_WORD
    } else if b == b'\n' {
        CTX_NEWLINE
    } else {
        0
    }
}

#[cfg(target_arch = "x86_64")]
static AVX2: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

#[cfg(target_arch = "x86_64")]
fn has_avx2() -> bool {
    match AVX2.load(Ordering::Relaxed) {
        1 => return false,
        2 => return true,
        _ => {}
    }
    let mut ok = false;
    unsafe {
        let leaf1 = core::arch::x86_64::__cpuid(1);
        if leaf1.ecx >> 27 & 1 != 0 && leaf1.ecx >> 28 & 1 != 0 {
            let (eax, _edx): (u32, u32);
            core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") eax, out("edx") _edx, options(nomem, nostack, preserves_flags));
            if eax & 6 == 6 && core::arch::x86_64::__cpuid_count(7, 0).ebx >> 5 & 1 != 0 {
                ok = true;
            }
        }
    }
    AVX2.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
    ok
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn skip_avx2(text: &[u8], from: usize, lo: &[u8; 16], hi: &[u8; 16]) -> usize {
    use core::arch::x86_64::*;
    unsafe {
        let len = text.len();
        let base = text.as_ptr();
        let lo_t = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo.as_ptr() as *const __m128i));
        let hi_t = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi.as_ptr() as *const __m128i));
        let nib = _mm256_set1_epi8(0x0f);
        let zero = _mm256_setzero_si256();
        let probe = |at: usize| -> u32 {
            let v = _mm256_loadu_si256(base.add(at) as *const __m256i);
            let l = _mm256_and_si256(v, nib);
            let h = _mm256_and_si256(_mm256_srli_epi16(v, 4), nib);
            let m = _mm256_and_si256(_mm256_shuffle_epi8(lo_t, l), _mm256_shuffle_epi8(hi_t, h));
            !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(m, zero)) as u32)
        };
        let mut i = from;
        while i + 32 <= len {
            let hit = probe(i);
            if hit != 0 {
                return i + hit.trailing_zeros() as usize;
            }
            i += 32;
        }
        if i < len {
            let at = len - 32;
            let hit = probe(at);
            if hit != 0 {
                return at + hit.trailing_zeros() as usize;
            }
        }
        len
    }
}

fn nibble_tables(set: &[u8; 256]) -> Option<([u8; 16], [u8; 16])> {
    let mut pats = [0u16; 8];
    let mut np = 0usize;
    let (mut lo, mut hi) = ([0u8; 16], [0u8; 16]);
    for h in 0..16usize {
        let mut m = 0u16;
        for l in 0..16usize {
            if set[h << 4 | l] != 0 {
                m |= 1 << l;
            }
        }
        if m == 0 {
            continue;
        }
        let k = match pats[..np].iter().position(|&x| x == m) {
            Some(k) => k,
            None => {
                if np == 8 {
                    return None;
                }
                pats[np] = m;
                np += 1;
                np - 1
            }
        };
        hi[h] = 1 << k;
    }
    for l in 0..16usize {
        for (k, &m) in pats[..np].iter().enumerate() {
            if m >> l & 1 != 0 {
                lo[l] |= 1 << k;
            }
        }
    }
    Some((lo, hi))
}

