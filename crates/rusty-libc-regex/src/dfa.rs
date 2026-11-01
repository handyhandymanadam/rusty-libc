//! A lazily built DFA that decides, in one pass over the text, whether a match exists at all and
//! where the interesting part of the text begins. It never decides *which* match glibc reports:
//! `exec::search_forward` still does that, but only on the window this module hands over.
//!
//! The automaton runs the same node sets as the matcher in `exec` (consumer nodes and end nodes,
//! after the epsilon closure, with the "previous context" constraints applied exactly as
//! `fwd_add` does), unanchored: a new start is injected at every position, so a state is the set
//! of nodes reachable from any start. Transitions depend only on the byte (through its class), so
//! they are built on demand and cached; acceptance additionally depends on the context of the next
//! character (glibc's end-node "next" constraints), which a state stores as a small bit mask.
//!
//! What the scan returns:
//! * no state ever accepted: there is no match (the matcher's fastmap rule can only remove
//!   matches, never add one), so the answer is "no match" without running the matcher;
//! * the first position `p1` where a state accepts, and `q`, the last position at or before `p1` where
//!   no thread of an earlier start was alive (the step into it had an empty successor set before
//!   the new start was injected). A match cannot start before `q`: such a match would have to be
//!   alive at `q`, or to have ended before `p1`. The matcher starts at `q` instead of at the
//!   beginning of the text, which for a match near the end of a large text skips almost all of
//!   the work.
//!
//! While no thread is alive (the common state in a long scan for a rare match) bytes that no
//! start node can consume are skipped with a table lookup.
//!
//! With the window known, a second DFA (anchored: no start is injected) finds the match itself the
//! way glibc does: the first start position from `q` on at which the automaton accepts somewhere
//! is the leftmost start, and the last accepting position of that run is its longest end. The
//! total work of those anchored runs is capped; past the cap the matcher takes over from `q`.
#![allow(clippy::needless_range_loop, clippy::collapsible_if)]
use crate::consts::*;
use crate::exec::Env;
use crate::nfa::*;
use crate::vec::V;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use rusty_libc_core::sync_cell::SyncCell;

/// Edge flag: the step had no successor before the new start was injected.
const PURE: u32 = 1 << 31;
/// Edge flag: the target state has an end node (acceptance depends on the next character).
const ACC: u32 = 1 << 30;
const UNKNOWN: u32 = u32::MAX;
/// States kept before the cache is thrown away.
const MAX_STATES: usize = 1200;
/// Entries of the edge table (4 bytes each) kept before the cache is thrown away: 4 MiB, whatever the number of classes.
const MAX_TRANS: usize = 1 << 20;
/// The state limit (a test lowers it to make the cache overflow all the time).
#[cfg(test)]
pub static TEST_STATE_CAP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(MAX_STATES);

#[inline]
fn state_cap() -> usize {
    #[cfg(test)]
    {
        TEST_STATE_CAP.load(Ordering::Relaxed)
    }
    #[cfg(not(test))]
    {
        MAX_STATES
    }
}

/// Patterns with more nodes than this keep to the plain matcher.
const MAX_NODES: usize = 3000;
/// Texts shorter than this are only searched with the DFA after `SHORT_CALLS` earlier searches.
pub const MIN_TEXT: usize = 64;
const SHORT_CALLS: u32 = 8;

pub enum Pre {
    /// No match anywhere in the text.
    NoMatch,
    /// A match exists; none starts before `q`. `p1` is the end of the earliest-ending match.
    Window { q: usize, p1: usize },
    /// The DFA cannot be used for this search (lock taken, memory, size limits).
    Unavailable,
}

/// What `Dfa::locate` found.
pub enum Loc {
    NoMatch,
    /// The leftmost-longest match.
    Found(usize, usize),
    /// A match exists and none starts before this position: the matcher continues from there.
    Window(usize),
    Unavailable,
}

pub struct Dfa {
    /// Held while a search uses `inner` (a try-lock: a search that finds it taken, because another thread is scanning with
    /// the same pattern, uses the NFA matcher instead). The flag and the cell are separate fields rather than a
    /// `sync::Spin`, so that `Dfa` (and with it `Compiled`, one malloc block per pattern) keeps its size: a `Spin` pads its
    /// flag to the cell's alignment, and the 8 extra bytes per pattern changed the heap's layout and its brk calls.
    lock: AtomicBool,
    /// Searches of short texts so far: building states for a regex that is used once or twice on a
    /// short text costs more than running the matcher, so the DFA only takes over after a few.
    short_calls: AtomicU32,
    /// The two automata (3 KB of tables each), made by the first search that gets this far: a pattern that is compiled and
    /// used once on a short text neither allocates nor copies them. Only touched while `lock` is held.
    inner: SyncCell<V<Both>>,
}

struct Both {
    fwd: Inner,
    anch: Inner,
}

impl Dfa {
    pub const fn new() -> Dfa {
        Dfa { lock: AtomicBool::new(false), short_calls: AtomicU32::new(0), inner: SyncCell::new(V::new()) }
    }

    /// Find the match of a search that starts at `start0` and may start anywhere up to the end of the
    /// text (see the module comment); `env.stop` must be the end of the text. Without `need_longest`
    /// only the existence of a match is certain: `Found` then carries some position pair.
    pub fn locate(&self, env: &Env, start0: usize, need_longest: bool) -> Loc {
        if env.nfa.nbackref != 0 || env.nfa.nodes.len() > MAX_NODES || env.stop != env.text.len() {
            return Loc::Unavailable;
        }
        // multibyte locale: the byte automaton is exact on text whose characters are single bytes; on other text `scan` decides
        // whether the pattern allows it. A charset with trail bytes below 0x80 needs all the text to be ASCII, because
        // `start0` may be inside a character.
        let mb = env.nfa.mb;
        let plain = mb == crate::charset::Mb::None || env.text[if mb == crate::charset::Mb::Other { 0 } else { start0.min(env.text.len()) }..].is_ascii();
        if !plain && mb == crate::charset::Mb::Other && env.starts().len() != env.text.len() + 1 {
            return Loc::Unavailable;
        }
        if env.text.len() - start0 < MIN_TEXT && self.short_calls.fetch_add(1, Ordering::Relaxed) < SHORT_CALLS {
            return Loc::Unavailable;
        }
        if self.lock.swap(true, Ordering::Acquire) {
            return Loc::Unavailable;
        }
        let run = |slot: &mut V<Both>| {
            if slot.is_empty() {
                slot.push(Both { fwd: Inner::new(false), anch: Inner::new(true) });
                if slot.oom {
                    return Loc::Unavailable;
                }
            }
            let both = &mut slot[0];
            match both.fwd.scan(env, start0, plain) {
                Pre::NoMatch => Loc::NoMatch,
                Pre::Unavailable => Loc::Unavailable,
                Pre::Window { q, p1 } => {
                    if !need_longest {
                        Loc::Found(q, p1)
                    } else {
                        both.anch.find(env, q, p1)
                    }
                }
            }
        };
        // SAFETY: we hold `lock`, and every access to `inner` takes it first, so nothing else touches the automata until
        // the release below; `run` does not reach this `Dfa` again.
        let r = unsafe { self.inner.with_unsync(run) };
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
    /// No start is injected: the automaton of one match attempt.
    anchored: bool,
    prepared: bool,
    disabled: bool,
    resets: u32,
    xlat: [u8; 256],
    /// The table was the compiled pattern's own (it never changes): later searches with that one need no comparison.
    xlat_fixed: bool,
    newline_anchor: bool,
    /// Class of a raw text byte (after translation).
    raw_cls: [u8; 256],
    ncls: usize,
    /// Edges per state row before the acceptance entry: `ncls << fw_shift`. The forward automaton of a pattern compiled in a
    /// non-UTF-8 multibyte charset has two edges per class, one for each answer to "does a character start at the next
    /// position" (a new match attempt is injected only there); every other automaton has one.
    width: u32,
    fw_shift: u32,
    /// The pattern can use the byte automaton on text with characters of several bytes (see `mb_text_ok`).
    mb_ok: bool,
    /// A translated byte of each class.
    rep: [u8; 256],
    /// `trans_ctx` of the class (what a consumed byte of this class gives the next state).
    cls_trans: [u8; 256],
    /// The real context (0, CTX_WORD or CTX_NEWLINE) of a byte of this class.
    cls_real: [u8; 256],
    /// Can this raw byte be consumed by a node of the initial closure (constraints ignored)?
    first_raw: [u8; 256],
    /// `first_raw` as two nibble tables (a byte is in the set when `lo[b & 15] & hi[b >> 4] != 0`),
    /// when the set fits eight patterns: for the vector skip loop.
    nib: bool,
    nib_lo: [u8; 16],
    nib_hi: [u8; 16],
    init_has_end: bool,
    // states
    arena: V<u32>,
    st_off: V<u32>,
    st_len: V<u32>,
    st_acc: V<u8>,
    trans: V<u32>,
    table: V<u32>,
    /// Initial state per tip context, and injection-only states per real context.
    init_ids: [(u8, u32); 8],
    n_init: usize,
    pure_ids: [u32; 3],
    /// The state with no node (no thread alive, no match attempt injected).
    empty_id: u32,
    // scratch
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
            width: 0,
            fw_shift: 0,
            mb_ok: false,
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
            empty_id: NOID,
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
        self.empty_id = NOID;
    }

    /// Byte classes and the per-class facts, for this pattern, translation and `newline_anchor`.
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
        // partition the translated bytes by everything a node or a context can tell apart
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
        // the first bytes of the UTF-8 sets, and the continuation bytes
        for sp in nfa.u8specs().iter() {
            if ncls < 256 {
                refine(&|b| crate::parse::set_has(&sp.root, b as u8), &mut cls, &mut ncls);
            }
        }
        if !nfa.u8specs().is_empty() && ncls < 256 {
            refine(&|b| (0x80..=0xbf).contains(&b), &mut cls, &mut ncls);
        }
        // the groups of the multibyte automata (each automaton once: its states are the same for every use)
        'frags: for f in nfa.frags().iter() {
            for (set, _) in f.groups.iter() {
                if ncls >= 256 {
                    break 'frags;
                }
                refine(&|b| crate::parse::set_has(set, b as u8), &mut cls, &mut ncls);
            }
        }
        self.ncls = ncls;
        self.fw_shift = u32::from(!self.anchored && nfa.mb == crate::charset::Mb::Other);
        self.width = (ncls as u32) << self.fw_shift;
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
        // first bytes: consumers of the initial closure
        self.first_raw = [0; 256];
        self.init_has_end = false;
        for &n in nfa.init_nodes.iter() {
            let nd = &nfa.nodes[n as usize];
            match nd.kind {
                K_END => self.init_has_end = true,
                K_CHAR | K_SET | K_ANY | K_MB | K_U8 => {
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
        // text with multibyte characters: the automaton runs on bytes, which is the matcher's reading of the pattern when
        // no node looks at a whole character (word contexts, the UTF-8 sets that read the bytes before) and when a match
        // attempt cannot start inside a character: in UTF-8 no start node takes a continuation byte, in the other charsets
        // the flagged edges inject attempts at character starts only
        self.mb_ok = nfa.mb != crate::charset::Mb::None
            && !nfa.word_ctx
            && nfa.u8specs().is_empty()
            && !self.init_has_end
            && (nfa.mb == crate::charset::Mb::Other || !self.first_raw[0x80..0xc0].iter().any(|&x| x != 0));
        self.mark = V::from_elem(0, nfa.nodes.len());
        self.generation = 0;
        if self.mark.oom {
            self.mark = V::new();
            return false;
        }
        self.prepared = true;
        true
    }

    /// The first index at or after `from` whose byte can start a match (`text.len()` if none).
    #[inline]
    fn skip(&self, text: &[u8], from: usize) -> usize {
        #[cfg(target_arch = "x86_64")]
        if self.nib && text.len() - from >= 32 && has_avx2() {
            // SAFETY: AVX2 is available and at least 32 bytes remain after `from` (both checked just above).
            return unsafe { skip_avx2(text, from, &self.nib_lo, &self.nib_hi) };
        }
        let fr = &self.first_raw;
        let mut i = from;
        while i < text.len() {
            // (no bounds checks: `i < len` is the loop condition, and a byte indexes the 256-entry table)
            if fr[text[i] as usize] != 0 {
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

    /// Add node `x` to the scratch list (when it is a consumer or an end node and its "previous"
    /// constraint holds under `ctx`), like `fwd_add`.
    fn add(&mut self, nfa: &Nfa, x: u32, ctx: u8) {
        if self.mark[x as usize] == self.generation {
            return;
        }
        let nd = &nfa.nodes[x as usize];
        if nd.constraint != 0 && prev_bad(nd.constraint, ctx) {
            return;
        }
        self.mark[x as usize] = self.generation;
        if matches!(nd.kind, K_CHAR | K_SET | K_ANY | K_MB | K_U8 | K_END) {
            self.scratch.push(x);
        }
    }

    /// The state with the node set in `scratch` (sorted here); None when memory or the state limit runs out.
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
        if self.st_off.len() >= state_cap() || self.trans.len() >= MAX_TRANS {
            return None;
        }
        // a new state: its acceptance mask (bit per next-character context: 0 other, 1 word,
        // 2 newline, 3 end of text with an end of line, 4 end of text without)
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
        // a row: one edge per class, then the acceptance mask
        let new_len = self.trans.len() + self.width as usize + 1;
        self.trans.resize(new_len, UNKNOWN);
        self.trans[new_len - 1] = u32::from(acc);
        if self.arena.oom || self.st_off.oom || self.st_len.oom || self.st_acc.oom || self.trans.oom {
            return None;
        }
        self.table[i] = id;
        Some(id)
    }

    /// The state a match attempt starts in when the context of the character before is `tip`.
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

    /// The injection-only state after a byte whose real context is `rc` (0, CTX_WORD, CTX_NEWLINE).
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

    /// The state with no node: no thread alive and no match attempt started at the position.
    fn empty_state(&mut self, nfa: &Nfa) -> Option<u32> {
        if self.empty_id != NOID {
            return Some(self.empty_id);
        }
        self.scratch.clear();
        let id = self.intern(nfa)?;
        self.empty_id = id;
        Some(id)
    }

    /// Build the transition of the state at table offset `s_off` on edge `idx` (the class, and with `fw_shift` the flag
    /// "a character starts at the next position" in the low bit); the edge value is the target's table offset plus the
    /// PURE and ACC flags.
    fn step(&mut self, env: &Env, s_off: u32, idx: usize) -> Option<u32> {
        let nfa = env.nfa;
        let c = idx >> self.fw_shift;
        let inject = !self.anchored && (self.fw_shift == 0 || idx & 1 != 0);
        let s = s_off / (self.width + 1);
        let b = self.rep[c];
        let pc = self.cls_trans[c];
        self.scratch.clear();
        self.generation += 1;
        let (lo, hi) = self.state_nodes(s);
        for k in lo..hi {
            let n = self.arena[k];
            let nd = &nfa.nodes[n as usize];
            if matches!(nd.kind, K_CHAR | K_SET | K_ANY | K_MB | K_U8) && env.consume_dfa(nd, b) {
                for &x in nfa.eclosure(nfa.next_of(nd, b)) {
                    self.add(nfa, x, pc);
                }
            }
        }
        let pure = self.scratch.is_empty();
        if inject {
            // the next start, at the position after this byte
            let rc = self.cls_real[c];
            for &x in nfa.init_nodes.iter() {
                self.add(nfa, x, rc);
            }
        }
        let id = self.intern(nfa)?;
        let mut t = id * (self.width + 1);
        if pure {
            t |= PURE;
        }
        if self.st_acc[id as usize] != 0 {
            t |= ACC;
        }
        self.trans[(s_off as usize) + idx] = t;
        Some(t)
    }

    /// `plain`: the text from `start0` on (in a charset with multi-byte characters, all of it) is ASCII, so every byte
    /// is a character; otherwise the pattern must pass `mb_ok`.
    fn scan(&mut self, env: &Env, start0: usize, plain: bool) -> Pre {
        if !self.prepare(env) {
            return Pre::Unavailable;
        }
        if plain {
            self.scan_run::<false>(env, start0)
        } else if self.mb_ok {
            // (only the flagged automaton reads the table of character starts)
            if self.fw_shift != 0 { self.scan_run::<true>(env, start0) } else { self.scan_run::<false>(env, start0) }
        } else {
            Pre::Unavailable
        }
    }

    /// The scan of `scan`; `STARTS`: a match attempt is injected only where `env.starts` says a character starts.
    fn scan_run<const STARTS: bool>(&mut self, env: &Env, start0: usize) -> Pre {
        let nfa = env.nfa;
        let text = env.text;
        let len = text.len();
        let ncls = self.width;
        let stride = ncls + 1;
        let shift = self.fw_shift;
        // the flag of every edge when the text is plain: a character starts everywhere
        let flag_plain = usize::from(shift != 0);
        let starts: &[u64] = if STARTS { env.starts().words() } else { &[] };
        let first = if STARTS && starts[start0 >> 6] >> (start0 & 63) & 1 == 0 { self.empty_state(nfa) } else { self.init_state(nfa, env.tip_ctx(start0)) };
        let Some(init) = first else {
            return self.give_up();
        };
        let mut off = init * stride;
        let mut p = start0;
        let mut q = start0;
        let mut pure_now = true;
        let mut check = true;
        loop {
            if pure_now && !self.init_has_end {
                // no thread alive: bytes no start node can consume are skipped
                let mut i = self.skip(text, p);
                if STARTS {
                    // (a byte inside a character starts no attempt)
                    while i < len && starts[i >> 6] >> (i & 63) & 1 == 0 {
                        i = self.skip(text, i + 1);
                    }
                }
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
            // the fast loop: plain edges only
            loop {
                if p == len {
                    return Pre::NoMatch;
                }
                let c = self.raw_cls[text[p] as usize] as usize;
                let idx = if STARTS { c << shift | (starts[(p + 1) >> 6] >> ((p + 1) & 63) & 1) as usize } else { c << shift | flag_plain };
                let t = self.trans[off as usize + idx];
                if t & (PURE | ACC) == 0 {
                    off = t;
                    p += 1;
                    continue;
                }
                let t = if t == UNKNOWN {
                    match self.step(env, off, idx) {
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

    /// The anchored automaton: the leftmost-longest match in `q..=p1` (the start is the first position
    /// from `q` with an accepting run; the end is the last accepting position of that run).
    fn find(&mut self, env: &Env, q: usize, p1: usize) -> Loc {
        if !self.prepare(env) {
            return Loc::Window(q);
        }
        let nfa = env.nfa;
        let text = env.text;
        let len = text.len();
        let ncls = self.width;
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
                            // the successor set is empty: the run is over
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
        // no start in the window gave a match (the matcher's start filter can do that): let the matcher decide
        Loc::Window(q)
    }

    /// The state limit or memory ran out: drop the cache; a pattern that keeps doing that stops using the DFA.
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

/// Equal 256-byte tables (word-wise: no library call).
#[inline]
fn same_table(a: &[u8; 256], b: &[u8; 256]) -> bool {
    let mut diff = 0u64;
    for (x, y) in a.as_chunks::<8>().0.iter().zip(b.as_chunks::<8>().0) {
        diff |= u64::from_ne_bytes(*x) ^ u64::from_ne_bytes(*y);
    }
    diff == 0
}

/// The context a DFA state gets from the character consumed to reach it (see `Env::trans_ctx`).
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

/// AVX2 usable (CPU feature and operating system support for the YMM registers), detected once.
#[cfg(target_arch = "x86_64")]
fn has_avx2() -> bool {
    match AVX2.load(Ordering::Relaxed) {
        1 => return false,
        2 => return true,
        _ => {}
    }
    let mut ok = false;
    let leaf1 = core::arch::x86_64::__cpuid(1);
    if leaf1.ecx >> 27 & 1 != 0 && leaf1.ecx >> 28 & 1 != 0 {
        let (eax, _edx): (u32, u32);
        // SAFETY: OSXSAVE (CPUID.1:ECX bit 27) is set, so xgetbv with ecx 0 is a valid instruction; it only reads XCR0.
        unsafe { core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") eax, out("edx") _edx, options(nomem, nostack, preserves_flags)) };
        if eax & 6 == 6 && core::arch::x86_64::__cpuid_count(7, 0).ebx >> 5 & 1 != 0 {
            ok = true;
        }
    }
    AVX2.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
    ok
}

/// First index at or after `from` of a byte in the set given by the nibble tables, or `text.len()`.
///
/// # Safety
/// AVX2 must be available and `text.len() - from >= 32`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn skip_avx2(text: &[u8], from: usize, lo: &[u8; 16], hi: &[u8; 16]) -> usize {
    use core::arch::x86_64::*;
    let len = text.len();
    let base = text.as_ptr();
    // SAFETY: `lo` is 16 readable bytes (an unaligned load).
    let lo_v = unsafe { _mm_loadu_si128(lo.as_ptr().cast::<__m128i>()) };
    // SAFETY: `hi` is 16 readable bytes.
    let hi_v = unsafe { _mm_loadu_si128(hi.as_ptr().cast::<__m128i>()) };
    let lo_t = _mm256_broadcastsi128_si256(lo_v);
    let hi_t = _mm256_broadcastsi128_si256(hi_v);
    let nib = _mm256_set1_epi8(0x0f);
    let zero = _mm256_setzero_si256();
    // (the value intrinsics are safe calls here: AVX2 is enabled for this function and the closure inside it)
    let probe = |at: usize| -> u32 {
        // SAFETY: every caller passes `at + 32 <= len`, so the 32 bytes are inside `text`.
        let v = unsafe { _mm256_loadu_si256(base.wrapping_add(at).cast::<__m256i>()) };
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
        // the last, overlapping block (bytes before `i` were already seen to be misses; `len >= 32` by the contract)
        let at = len - 32;
        let hit = probe(at);
        if hit != 0 {
            return at + hit.trailing_zeros() as usize;
        }
    }
    len
}

/// Nibble tables for the byte set `set` (non-zero entries), when it needs at most eight patterns of
/// low nibbles: a byte is in the set exactly when `lo[b & 15] & hi[b >> 4] != 0`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nibble_tables_and_vector_skip_agree_with_the_table_scan() {
        let mut st = 0x1357_9bdf_2468_ace0u64;
        let mut rnd = move || {
            st ^= st >> 12;
            st ^= st << 25;
            st ^= st >> 27;
            st.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut encodable = 0;
        for round in 0..4000 {
            // sets: a few bytes, ranges, or classes of ASCII
            let mut set = [0u8; 256];
            match round % 4 {
                0 => (0..1 + rnd() % 4).for_each(|_| set[(rnd() % 256) as usize] = 1),
                1 => {
                    let a = (rnd() % 200) as usize;
                    (a..a + (rnd() % 40) as usize).for_each(|b| set[b] = 1)
                }
                2 => (0..256usize).for_each(|b| set[b] = u8::from(b < 128 && (b as u8).is_ascii_alphanumeric())),
                _ => (0..256usize).for_each(|b| set[b] = u8::from(rnd() % 7 == 0)),
            }
            let Some((lo, hi)) = nibble_tables(&set) else { continue };
            encodable += 1;
            for b in 0..256usize {
                assert_eq!(lo[b & 15] & hi[b >> 4] != 0, set[b] != 0, "byte {b}");
            }
            // texts of various lengths and hit positions, including the overlapping tail block
            let len = 32 + (rnd() % 200) as usize;
            let mut text: Vec<u8> = (0..len).map(|_| loop {
                let b = rnd() as u8;
                if set[b as usize] == 0 {
                    break b;
                }
            }).collect();
            if rnd() % 3 != 0 {
                if let Some(b) = (0..=255u8).find(|&b| set[b as usize] != 0) {
                    let at = (rnd() % len as u64) as usize;
                    text[at] = b;
                }
            }
            let from = (rnd() % (len as u64 - 31)) as usize;
            let want = (from..len).find(|&i| set[text[i] as usize] != 0).unwrap_or(len);
            #[cfg(target_arch = "x86_64")]
            if has_avx2() {
                // SAFETY: AVX2 checked, len - from >= 32.
                assert_eq!(unsafe { skip_avx2(&text, from, &lo, &hi) }, want, "len {len} from {from}");
            }
        }
        assert!(encodable > 1000);
    }
}
