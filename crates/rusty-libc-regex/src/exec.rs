use crate::charset::{self, Mb};
use crate::consts::*;
use crate::dfa::Loc;
use crate::nfa::*;
use crate::parse::ctxbits::*;
use crate::parse::{NONE, set_has};
use crate::vec::V;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct Reg {
    pub so: i32,
    pub eo: i32,
}

pub const UNSET: Reg = Reg { so: -1, eo: -1 };

pub struct Env<'a> {
    pub nfa: &'a Nfa,
    pub text: &'a [u8],
    pub xlat: &'a [u8; 256],
    pub xlat_fixed: bool,
    pub fastmap: Option<&'a [u8; 256]>,
    pub fm_trans: Option<&'a [u8; 256]>,
    pub stop: usize,
    pub not_bol: bool,
    pub not_eol: bool,
    pub newline_anchor: bool,
    pub starts: V<u8>,
}

impl<'a> Env<'a> {
    pub fn char_starts(nfa: &Nfa, text: &[u8]) -> V<u8> {
        let mut v: V<u8> = V::new();
        if nfa.mb != Mb::Other {
            return v;
        }
        v.resize(text.len() + 1, 0);
        let mut i = 0;
        while i < text.len() {
            v[i] = 1;
            let n = match charset::decode(Mb::Other, &text[i..text.len().min(i + 6)]) {
                Some((_, n)) => n,
                None => 1,
            };
            i += n.max(1);
        }
        v[text.len()] = 1;
        v
    }

    fn char_info(&self, i: usize) -> (usize, u32, usize) {
        let text = self.text;
        let b = text[i];
        if self.nfa.mb == Mb::Utf8 {
            if b < 0x80 {
                return (i, b as u32, 1);
            }
            let lo = i.saturating_sub(3);
            let mut j = i;
            loop {
                let c = text[j];
                if !(0x80..0xc0).contains(&c) {
                    if let Some((wc, n)) = charset::decode(Mb::Utf8, &text[j..text.len().min(j + 4)])
                        && j + n > i
                    {
                        return (j, wc, n);
                    }
                    break;
                }
                if j == lo {
                    break;
                }
                j -= 1;
            }
            return (i, b as u32, 1);
        }
        let mut j = i;
        while j > 0 && self.starts[j] == 0 {
            j -= 1;
        }
        match charset::decode(Mb::Other, &text[j..text.len().min(j + 6)]) {
            Some((wc, n)) if j + n > i => (j, wc, n),
            _ => (j, text[j] as u32, 1),
        }
    }

    #[inline]
    pub(crate) fn is_first(&self, i: usize) -> bool {
        if i >= self.text.len() {
            return true;
        }
        if self.nfa.mb == Mb::Utf8 {
            let b = self.text[i];
            return b < 0x80 || self.char_info(i).0 == i;
        }
        self.starts[i] != 0
    }

    fn mb_ctx(&self, i: usize) -> u8 {
        let (_, wc, _) = self.char_info(i);
        if charset::is_word_wc(wc) {
            CTX_WORD
        } else if wc == b'\n' as u32 && self.newline_anchor {
            CTX_NEWLINE
        } else {
            0
        }
    }

    #[inline]
    fn tb(&self, i: usize) -> u8 {
        self.xlat[self.text[i] as usize]
    }

    fn ctx_at(&self, i: usize) -> u8 {
        if i >= self.text.len() {
            return CTX_ENDBUF | if self.not_eol { 0 } else { CTX_NEWLINE };
        }
        if self.nfa.mb != Mb::None {
            return self.mb_ctx(i);
        }
        let b = self.tb(i);
        if charset::is_word(b) {
            CTX_WORD
        } else if b == b'\n' && self.newline_anchor {
            CTX_NEWLINE
        } else {
            0
        }
    }

    pub(crate) fn tip_ctx(&self, p: usize) -> u8 {
        if p == 0 { CTX_BEGBUF | if self.not_bol { 0 } else { CTX_NEWLINE } } else { self.ctx_at(p - 1) }
    }

    #[inline]
    fn trans_ctx_at(&self, p: usize, b: u8) -> u8 {
        if self.nfa.mb == Mb::None || (self.nfa.mb == Mb::Utf8 && b < 0x80) {
            return Self::trans_ctx(b);
        }
        let (s, wc, n) = self.char_info(p);
        if s + n != p + 1 {
            return 0;
        }
        if charset::is_word_wc(wc) {
            CTX_WORD
        } else if wc == b'\n' as u32 {
            CTX_NEWLINE
        } else {
            0
        }
    }

    #[inline]
    pub(crate) fn consume_at(&self, nd: &NNode, b: u8, p: usize) -> bool {
        if self.nfa.mb != Mb::None && nd.constraint & (NEXT_WORD | NEXT_NOTWORD) != 0 {
            if !self.accept_base(nd, b) {
                return false;
            }
            let c = nd.constraint;
            if c & NEXT_NEWLINE != 0 && b != b'\n' {
                return false;
            }
            if c & NEXT_ENDBUF != 0 {
                return false;
            }
            let (_, wc, _) = self.char_info(p);
            let w = charset::is_word_wc(wc);
            if (c & NEXT_WORD != 0 && !w) || (c & NEXT_NOTWORD != 0 && w) {
                return false;
            }
            return true;
        }
        self.consume_dfa(nd, b)
    }

    fn trans_ctx(b: u8) -> u8 {
        if charset::is_word(b) {
            CTX_WORD
        } else if b == b'\n' {
            CTX_NEWLINE
        } else {
            0
        }
    }

    #[inline]
    pub(crate) fn accept_base(&self, nd: &NNode, b: u8) -> bool {
        match nd.kind {
            K_CHAR => nd.c == b,
            K_SET => set_has(&self.nfa.sets[nd.arg as usize], b),
            K_ANY => !(b == b'\n' && self.nfa.syntax & RE_DOT_NEWLINE == 0) && !(b == 0 && self.nfa.syntax & RE_DOT_NOT_NULL != 0),
            _ => false,
        }
    }

    #[inline]
    pub(crate) fn consume_dfa(&self, nd: &NNode, b: u8) -> bool {
        if !self.accept_base(nd, b) {
            return false;
        }
        let c = nd.constraint;
        if c != 0 {
            if c & NEXT_NEWLINE != 0 && b != b'\n' {
                return false;
            }
            if c & NEXT_ENDBUF != 0 {
                return false;
            }
            if c & NEXT_WORD != 0 && !charset::is_word(b) {
                return false;
            }
            if c & NEXT_NOTWORD != 0 && charset::is_word(b) {
                return false;
            }
        }
        true
    }

    fn accept_real(&self, nd: &NNode, idx: usize) -> bool {
        if idx >= self.stop.min(self.text.len()) {
            return false;
        }
        if !self.accept_base(nd, self.tb(idx)) {
            return false;
        }
        if nd.constraint != 0 && next_bad(nd.constraint, self.ctx_at(idx)) {
            return false;
        }
        true
    }

    fn halt_ok(&self, nd: &NNode, p: usize) -> bool {
        nd.constraint == 0 || !next_bad(nd.constraint, self.ctx_at(p))
    }

    #[inline]
    pub(crate) fn start_ok(&self, q: usize) -> bool {
        if self.nfa.mb != Mb::None && !self.is_first(q) {
            return false;
        }
        match self.fastmap {
            None => true,
            Some(fm) => {
                let ch = if q < self.text.len() { self.text[q] } else { 0 };
                let i = match self.fm_trans {
                    Some(t) => t[ch as usize],
                    None => ch,
                };
                fm[i as usize] != 0
            }
        }
    }
}

pub struct Scratch {
    nodes: usize,
    mark: V<u32>,
    generation: u32,
    cur: V<(u32, u32)>,
    next: V<(u32, u32)>,
}

impl Scratch {
    pub fn new(nodes: usize) -> Scratch {
        Scratch { nodes, mark: V::new(), generation: 0, cur: V::new(), next: V::new() }
    }
}

type Best = Option<(u32, usize)>;

#[allow(clippy::too_many_arguments)]
fn fwd_add(env: &Env, mark: &mut V<u32>, generation: u32, list: &mut V<(u32, u32)>, nodes: &[u32], start: u32, p: usize, prevctx: u8, best: &mut Best) {
    for &n in nodes {
        if mark[n as usize] == generation {
            continue;
        }
        let nd = &env.nfa.nodes[n as usize];
        if nd.constraint != 0 && prev_bad(nd.constraint, prevctx) {
            continue;
        }
        mark[n as usize] = generation;
        match nd.kind {
            K_CHAR | K_SET | K_ANY => list.push((n, start)),
            K_END if env.halt_ok(nd, p) => {
                let better = match *best {
                    None => true,
                    Some((bs, be)) => start < bs || (start == bs && p > be),
                };
                if better {
                    *best = Some((start, p));
                }
            }
            _ => {}
        }
    }
}

fn search_forward(env: &Env, start0: usize, last_start: usize, need_longest: bool, sc: &mut Scratch) -> Result<Option<(usize, usize)>, i32> {
    let nfa = env.nfa;
    let stop = env.stop;
    let mut start0 = start0;
    if last_start == env.text.len() {
        match nfa.dfa.locate(env, start0, need_longest) {
            Loc::NoMatch => return Ok(None),
            Loc::Found(s, e) => return Ok(Some((s, e))),
            Loc::Window(q) => start0 = q,
            Loc::Unavailable => {}
        }
    }
    if sc.mark.len() != sc.nodes {
        sc.mark = V::from_elem(0, sc.nodes);
        if sc.mark.oom {
            return Err(REG_ESPACE);
        }
    }
    let mut best: Best = None;
    let mut p = start0;
    sc.generation += 1;
    sc.cur.clear();
    loop {
        if best.is_none() && p <= last_start && env.start_ok(p) {
            let pc = env.tip_ctx(p);
            fwd_add(env, &mut sc.mark, sc.generation, &mut sc.cur, &nfa.init_nodes, p as u32, p, pc, &mut best);
        }
        if best.is_some() && !need_longest {
            break;
        }
        if sc.cur.is_empty() || p >= stop {
            if best.is_some() || p >= last_start {
                break;
            }
            sc.cur.clear();
            let mut q = p + 1;
            while q < last_start && !env.start_ok(q) {
                q += 1;
            }
            p = q;
            sc.generation += 1;
            continue;
        }
        let b = env.tb(p);
        let pc = env.trans_ctx_at(p, b);
        sc.generation += 1;
        sc.next.clear();
        for i in 0..sc.cur.len() {
            let (n, s) = sc.cur[i];
            if let Some((bs, _)) = best
                && s > bs
            {
                continue;
            }
            let nd = &nfa.nodes[n as usize];
            if env.consume_at(nd, b, p) {
                fwd_add(env, &mut sc.mark, sc.generation, &mut sc.next, nfa.eclosure(nd.next), s, p + 1, pc, &mut best);
            }
        }
        core::mem::swap(&mut sc.cur, &mut sc.next);
        p += 1;
    }
    if sc.cur.oom || sc.next.oom {
        return Err(REG_ESPACE);
    }
    Ok(best.map(|(s, e)| (s as usize, e)))
}

#[inline]
fn bit(rows: &[u64], w: usize, r: usize, n: usize) -> bool {
    rows[r * w + n / 64] >> (n % 64) & 1 != 0
}

#[inline]
fn setbit(rows: &mut [u64], w: usize, r: usize, n: usize) {
    rows[r * w + n / 64] |= 1 << (n % 64);
}

fn fwd_rows(env: &Env, s: usize, e: usize) -> Result<V<u64>, i32> {
    let nfa = env.nfa;
    let m = nfa.nodes.len();
    let w = m.div_ceil(64);
    let rows = e - s + 1;
    if rows.checked_mul(w).is_none_or(|x| x > (1usize << 28)) {
        return Err(REG_ESPACE);
    }
    let mut bits: V<u64> = V::from_elem(0, rows * w);
    if bits.oom {
        return Err(REG_ESPACE);
    }
    let mut st: V<u32> = V::new();
    nfa.init_state(env.tip_ctx(s), &mut st);
    for &n in st.iter() {
        setbit(&mut bits, w, 0, n as usize);
    }
    for p in s..e {
        let r = p - s;
        let b = env.tb(p);
        let pc = env.trans_ctx_at(p, b);
        for wi in 0..w {
            let mut word = bits[r * w + wi];
            while word != 0 {
                let bi = word.trailing_zeros() as usize;
                word &= word - 1;
                let n = wi * 64 + bi;
                let nd = &nfa.nodes[n];
                if matches!(nd.kind, K_CHAR | K_SET | K_ANY) && env.consume_at(nd, b, p) {
                    for &x in nfa.eclosure(nd.next) {
                        let c = nfa.nodes[x as usize].constraint;
                        if c != 0 && prev_bad(c, pc) {
                            continue;
                        }
                        setbit(&mut bits, w, r + 1, x as usize);
                    }
                }
            }
        }
    }
    Ok(bits)
}

fn sift(env: &Env, rows: &V<u64>, s: usize, e: usize, last_node: u32) -> Result<Option<V<u64>>, i32> {
    let nfa = env.nfa;
    let m = nfa.nodes.len();
    let w = m.div_ceil(64);
    let nrows = e - s + 1;
    let mut out: V<u64> = V::from_elem(0, nrows * w);
    if out.oom {
        return Err(REG_ESPACE);
    }
    let mut mark: V<u32> = V::from_elem(0, m);
    let mut generation = 0u32;
    let mut dest: V<u32> = V::new();
    let mut idx = e;
    loop {
        let r = idx - s;
        dest.clear();
        if idx == e {
            dest.push(last_node);
        } else {
            for wi in 0..w {
                let mut word = rows[r * w + wi];
                while word != 0 {
                    let bi = word.trailing_zeros() as usize;
                    word &= word - 1;
                    let n = wi * 64 + bi;
                    let nd = &nfa.nodes[n];
                    if matches!(nd.kind, K_CHAR | K_SET | K_ANY) && env.accept_real(nd, idx) && bit(&out, w, r + 1, nd.next as usize) {
                        dest.push(n as u32);
                    }
                }
            }
        }
        if !dest.is_empty() {
            generation += 1;
            for &d in dest.iter() {
                mark[d as usize] = generation;
            }
            for wi in 0..w {
                let mut word = rows[r * w + wi];
                while word != 0 {
                    let bi = word.trailing_zeros() as usize;
                    word &= word - 1;
                    let n = wi * 64 + bi;
                    if mark[n] == generation || nfa.eclosure(n as u32).iter().any(|&x| mark[x as usize] == generation) {
                        setbit(&mut out, w, r, n);
                    }
                }
            }
        }
        if idx == s {
            break;
        }
        idx -= 1;
    }
    if dest.oom || mark.oom {
        return Err(REG_ESPACE);
    }
    let any = out[..w].iter().any(|&x| x != 0);
    Ok(if any { Some(out) } else { None })
}

fn update_regs(nd: &NNode, regs: &mut [Reg], prev: &mut [Reg], idx: i32) {
    let nmatch = regs.len();
    if nd.kind == K_OPEN {
        let reg_num = nd.arg as usize + 1;
        if reg_num < nmatch {
            regs[reg_num].so = idx;
            regs[reg_num].eo = -1;
        }
    } else if nd.kind == K_CLOSE {
        let reg_num = nd.arg as usize + 1;
        if reg_num < nmatch {
            if regs[reg_num].so < idx {
                regs[reg_num].eo = idx;
                prev.copy_from_slice(regs);
            } else if nd.opt && prev[reg_num].so != -1 {
                regs.copy_from_slice(prev);
            } else {
                regs[reg_num].eo = idx;
            }
        }
    }
}

fn walk_regs(env: &Env, s: usize, e: usize, rows: &V<u64>, last_node: u32, regs: &mut [Reg]) -> bool {
    let nfa = env.nfa;
    let m = nfa.nodes.len();
    let w = m.div_ceil(64);
    let in_set = |cand: u32, idx: usize| -> bool { idx >= s && idx <= e && bit(rows, w, idx - s, cand as usize) };
    let mut prev: V<Reg> = V::new();
    prev.extend_from_slice(regs);
    let mut eps_mark: V<u32> = V::from_elem(0, m);
    let mut egen = 1u32;
    let mut cur = nfa.init;
    let mut idx = s;
    let mut steps: u64 = 0;
    let cap: u64 = ((e - s + 2) as u64).saturating_mul(m as u64 + 2).saturating_mul(4).saturating_add(1000);
    loop {
        let nd = &nfa.nodes[cur as usize];
        update_regs(nd, regs, &mut prev, idx as i32);
        if idx == e && cur == last_node {
            return true;
        }
        steps += 1;
        if steps > cap {
            return false;
        }
        if nd.is_eps() {
            eps_mark[cur as usize] = egen;
            let mut dest = NONE;
            for &cand in nd.edests() {
                if !in_set(cand, idx) {
                    continue;
                }
                if dest == NONE {
                    dest = cand;
                } else {
                    if eps_mark[dest as usize] == egen {
                        dest = cand;
                    }
                    break;
                }
            }
            if dest == NONE {
                return false;
            }
            cur = dest;
        } else if matches!(nd.kind, K_CHAR | K_SET | K_ANY) && env.accept_real(nd, idx) {
            cur = nd.next;
            idx += 1;
            egen += 1;
        } else {
            return false;
        }
    }
}

pub const BK_BUDGET: u64 = 8_000_000;

struct Frame {
    idx: usize,
    node: u32,
    regs: V<Reg>,
    prev: V<Reg>,
    eps: V<u32>,
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

struct Memo {
    tab: V<u64>,
    n: usize,
}

impl Memo {
    fn new() -> Memo {
        Memo { tab: V::from_elem(0, 1024), n: 0 }
    }
    fn insert(&mut self, key: u64) -> bool {
        let key = key | 1;
        if self.n >= (1 << 22) || self.tab.oom || self.tab.len() < 2 {
            return true;
        }
        if self.n * 2 >= self.tab.len() {
            let old = core::mem::take(&mut self.tab);
            let nl = old.len() * 2;
            self.tab = V::from_elem(0, nl);
            if self.tab.oom || self.tab.len() != nl {
                self.n = 1 << 22;
                return true;
            }
            for &k in old.iter() {
                if k != 0 {
                    let mut i = (mix(k) as usize) & (nl - 1);
                    while self.tab[i] != 0 {
                        i = (i + 1) & (nl - 1);
                    }
                    self.tab[i] = k;
                }
            }
        }
        let l = self.tab.len();
        let mut i = (mix(key) as usize) & (l - 1);
        loop {
            if self.tab[i] == key {
                return false;
            }
            if self.tab[i] == 0 {
                self.tab[i] = key;
                self.n += 1;
                return true;
            }
            i = (i + 1) & (l - 1);
        }
    }
}

fn guard_hit(env: &Env, g: usize, idx: usize) -> bool {
    let (rest, n) = env.nfa.guards[g];
    let n = n as usize;
    idx + n <= env.stop && (0..n).all(|k| env.tb(idx + k) == rest[k])
}

fn bk_at(env: &Env, s: usize, budget: &mut u64) -> Result<Option<(usize, V<Reg>)>, i32> {
    let nfa = env.nfa;
    let nreg = nfa.nsub as usize + 1;
    let mut regs: V<Reg> = V::from_elem(UNSET, nreg);
    let mut prev: V<Reg> = V::from_elem(UNSET, nreg);
    let mut eps: V<u32> = V::new();
    let mut stack: V<Frame> = V::new();
    let mut cur = nfa.init;
    let mut idx = s;
    let mut best_end: Option<usize> = None;
    let mut best_regs: V<Reg> = V::new();
    let mut memo = Memo::new();
    loop {
        if *budget == 0 || stack.len() > (1 << 21) {
            return Err(REG_ESPACE);
        }
        *budget -= 1;
        let nd = &nfa.nodes[cur as usize];
        update_regs(nd, &mut regs, &mut prev, idx as i32);
        let mut nxt = NONE;
        let mut ok = true;
        if nd.constraint != 0 {
            let pc = if idx == s { env.tip_ctx(s) } else { env.trans_ctx_at(idx - 1, env.tb(idx - 1)) };
            if prev_bad(nd.constraint, pc) {
                ok = false;
            }
        }
        if !ok {
        } else if nd.kind == K_END {
            if env.halt_ok(nd, idx) && best_end.is_none_or(|b| idx > b) {
                best_end = Some(idx);
                best_regs = regs.duplicate();
            }
            ok = false;
        } else if eps.contains(&cur) || (nd.kind == K_GUARD && guard_hit(env, nd.arg as usize, idx)) {
            ok = false;
        } else if (nd.kind == K_ALT && nd.ne == 2) || nd.kind == K_BACKREF {
            let mut h = mix(cur as u64 ^ ((idx as u64) << 24));
            for g in 0..64usize {
                if nfa.ref_groups >> g & 1 != 0 && g + 1 < nreg {
                    h = mix(h ^ ((regs[g + 1].so as u32 as u64) << 32 | regs[g + 1].eo as u32 as u64));
                }
            }
            let mut es = 0u64;
            for &e in eps.iter() {
                es = es.wrapping_add(mix(e as u64));
            }
            h = mix(h ^ es);
            if !memo.insert(h) {
                ok = false;
            }
        }
        if ok {
            if nd.is_eps() {
                eps.push(cur);
                if nd.kind == K_ALT && nd.ne == 2 {
                    if eps.contains(&nd.e[0]) {
                        nxt = nd.e[1];
                    } else {
                        stack.push(Frame { idx, node: nd.e[1], regs: regs.duplicate(), prev: prev.duplicate(), eps: eps.duplicate() });
                        nxt = nd.e[0];
                    }
                } else if nd.ne > 0 {
                    nxt = nd.e[0];
                }
            } else if nd.kind == K_BACKREF {
                let g = nd.arg as usize + 1;
                if nd.constraint != 0 && next_bad(nd.constraint, env.ctx_at(idx)) {
                } else if g < nreg && regs[g].so != -1 && regs[g].eo != -1 {
                    let len = (regs[g].eo - regs[g].so) as usize;
                    if len == 0 {
                        eps.push(cur);
                        nxt = nd.e[0];
                    } else if idx + len <= env.stop {
                        let so = regs[g].so as usize;
                        let mut same = true;
                        for k in 0..len {
                            if env.tb(so + k) != env.tb(idx + k) {
                                same = false;
                                break;
                            }
                        }
                        if same {
                            idx += len;
                            eps.clear();
                            nxt = nd.next;
                        }
                    }
                }
            } else if matches!(nd.kind, K_CHAR | K_SET | K_ANY) && env.accept_real(nd, idx) {
                idx += 1;
                eps.clear();
                nxt = nd.next;
            }
        }
        if stack.oom || regs.oom || eps.oom {
            return Err(REG_ESPACE);
        }
        if nxt == NONE {
            match stack.pop() {
                None => break,
                Some(f) => {
                    idx = f.idx;
                    cur = f.node;
                    regs = f.regs;
                    prev = f.prev;
                    eps = f.eps;
                }
            }
        } else {
            cur = nxt;
        }
    }
    Ok(best_end.map(|e| (e, best_regs)))
}

fn has_constraint(nfa: &Nfa, set: &[u32]) -> bool {
    set.iter().any(|&n| nfa.nodes[n as usize].constraint != 0)
}

fn init_bump(env: &Env, s: usize) -> usize {
    let nfa = env.nfa;
    let mut entr: V<u32> = V::new();
    entr.extend_from_slice(&nfa.init_nodes);
    let tip = env.tip_ctx(s);
    let mut ctx_id = if has_constraint(nfa, &entr) { tip } else { 0 };
    let mut st: V<u32> = V::new();
    nfa.init_state(tip, &mut st);
    let mut k = 0usize;
    let mut p = s;
    while p < env.stop {
        let b = env.tb(p);
        let pc = env.trans_ctx_at(p, b);
        let mut un: V<u32> = V::new();
        for &n in st.iter() {
            let nd = &nfa.nodes[n as usize];
            if matches!(nd.kind, K_CHAR | K_SET | K_ANY) && env.consume_at(nd, b, p) {
                let mut tmp: V<u32> = V::new();
                tmp.extend_from_slice(nfa.eclosure(nd.next));
                merge_sorted_pub(&mut un, &tmp);
            }
        }
        if un.is_empty() {
            break;
        }
        let nctx = if has_constraint(nfa, &un) { pc } else { 0 };
        if un.len() == entr.len() && un.iter().zip(entr.iter()).all(|(a, b)| a == b) && nctx == ctx_id {
            k = p + 1 - s;
        } else {
            break;
        }
        let mut f: V<u32> = V::new();
        for &n in un.iter() {
            let c = nfa.nodes[n as usize].constraint;
            if c != 0 && prev_bad(c, pc) {
                continue;
            }
            f.push(n);
        }
        st = f;
        entr = un;
        ctx_id = nctx;
        p += 1;
    }
    k
}

pub fn search_internal(env: &Env, start: isize, last_start: isize, nmatch_in: usize, pmatch: &mut [Reg]) -> i32 {
    let nfa = env.nfa;
    let nsub = nfa.nsub as usize;
    let extra = if nmatch_in > nsub { nmatch_in - (nsub + 1) } else { 0 };
    let nmatch = nmatch_in - extra;
    let need_longest = nmatch != 0 || nfa.nbackref > 0;
    let len = env.text.len();
    if start < 0 || last_start < 0 || start as usize > len || last_start as usize > len {
        return REG_NOMATCH;
    }
    let (start, last_start) = (start as usize, last_start as usize);
    let forward = start <= last_start;
    let want_regs = nmatch > 1;
    let prune = want_regs && nfa.has_plural;

    let mut sc = Scratch::new(nfa.nodes.len());
    let mut budget: u64 = BK_BUDGET;
    let mut cur_start = start;
    loop {
        let found: Option<(usize, usize, Option<V<Reg>>)> = if nfa.nbackref > 0 {
            let mut f = None;
            let mut s = cur_start;
            loop {
                if env.start_ok(s) {
                    match bk_at(env, s, &mut budget) {
                        Err(e) => return e,
                        Ok(Some((e, regs))) => {
                            f = Some((s, e, Some(regs)));
                            break;
                        }
                        Ok(None) => {}
                    }
                }
                if forward {
                    if s >= last_start {
                        break;
                    }
                    s += 1;
                } else {
                    if s <= last_start {
                        break;
                    }
                    s -= 1;
                }
            }
            f
        } else if forward {
            match search_forward(env, cur_start, last_start, need_longest, &mut sc) {
                Err(e) => return e,
                Ok(r) => r.map(|(s, e)| (s, e, None)),
            }
        } else {
            let mut f = None;
            let mut s = cur_start;
            loop {
                if env.start_ok(s) {
                    match search_forward(env, s, s, need_longest, &mut sc) {
                        Err(e) => return e,
                        Ok(Some((a, b))) => {
                            f = Some((a, b, None));
                            break;
                        }
                        Ok(None) => {}
                    }
                }
                if s <= last_start {
                    break;
                }
                s -= 1;
            }
            f
        };
        let (s, e, bk_regs) = match found {
            None => return REG_NOMATCH,
            Some(x) => x,
        };
        let bump = if bk_regs.is_none() && forward && need_longest && e == s && nfa.nbackref == 0 { init_bump(env, s) } else { 0 };
        if nmatch > 0 {
            let mut tmp: V<Reg> = V::from_elem(UNSET, nmatch);
            if tmp.oom {
                return REG_ESPACE;
            }
            tmp[0] = Reg { so: s as i32, eo: e as i32 };
            if want_regs {
                if let Some(br) = bk_regs {
                    for g in 1..nmatch {
                        tmp[g] = br[g];
                    }
                } else {
                    let rows = match fwd_rows(env, s, e) {
                        Ok(r) => r,
                        Err(c) => return c,
                    };
                    let w = nfa.nodes.len().div_ceil(64);
                    let mut last_node = NONE;
                    for n in 0..nfa.nodes.len() {
                        if bit(&rows, w, e - s, n) {
                            let nd = &nfa.nodes[n];
                            if nd.kind == K_END && env.halt_ok(nd, e) {
                                last_node = n as u32;
                                break;
                            }
                        }
                    }
                    if last_node == NONE {
                        return REG_NOMATCH;
                    }
                    let sifted;
                    let use_rows: &V<u64> = if prune {
                        match sift(env, &rows, s, e, last_node) {
                            Err(c) => return c,
                            Ok(None) => {
                                if forward {
                                    if s >= last_start {
                                        return REG_NOMATCH;
                                    }
                                    cur_start = s + 1;
                                } else {
                                    if s <= last_start || s == 0 {
                                        return REG_NOMATCH;
                                    }
                                    cur_start = s - 1;
                                }
                                continue;
                            }
                            Ok(Some(x)) => {
                                sifted = x;
                                &sifted
                            }
                        }
                    } else {
                        &rows
                    };
                    if !walk_regs(env, s, e, use_rows, last_node, &mut tmp) {
                        for (d, r) in pmatch[..nmatch].iter_mut().zip(tmp.iter()) {
                            d.so = if r.so == -1 { -1 } else { r.so - s as i32 };
                            d.eo = if r.eo == -1 { -1 } else { r.eo - s as i32 };
                        }
                        return REG_NOMATCH;
                    }
                }
            }
            if !nfa.subexp_map.is_empty() {
                for g in 0..nmatch.saturating_sub(1) {
                    let m = nfa.subexp_map[g] as usize;
                    if m != g {
                        tmp[g + 1] = tmp[m + 1];
                    }
                }
            }
            if bump > 0 {
                for r in tmp.iter_mut() {
                    if r.so != -1 {
                        r.so += bump as i32;
                    }
                    if r.eo != -1 {
                        r.eo += bump as i32;
                    }
                }
            }
            pmatch[..nmatch].copy_from_slice(&tmp);
            for r in pmatch[nmatch..nmatch + extra].iter_mut() {
                *r = UNSET;
            }
        }
        return REG_NOERROR;
    }
}
