//! Differential tests against the host glibc (C locale): thousands of random ERE/BRE patterns and
//! inputs generated from a grammar, glibc's own rxspencer/BOOST/PCRE vectors, the GNU re_*
//! interface, regerror, struct layout. Every comparison is "our result == host result".
// (test code calls the C interface of both libraries directly; the crate's SAFETY-per-block rule is for library code)
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::cabi::*;
use crate::consts::*;
use core::ffi::{c_char, c_int, c_ulong};
use std::ffi::CStr;

unsafe extern "C" {
    #[link_name = "regcomp"]
    fn host_regcomp(preg: *mut RegexT, pattern: *const c_char, cflags: c_int) -> c_int;
    #[link_name = "regexec"]
    fn host_regexec(preg: *const RegexT, string: *const c_char, nmatch: usize, pmatch: *mut RegMatch, eflags: c_int) -> c_int;
    #[link_name = "regerror"]
    fn host_regerror(code: c_int, preg: *const RegexT, buf: *mut c_char, size: usize) -> usize;
    #[link_name = "regfree"]
    fn host_regfree(preg: *mut RegexT);
    #[link_name = "re_set_syntax"]
    fn host_re_set_syntax(s: c_ulong) -> c_ulong;
    #[link_name = "re_compile_pattern"]
    fn host_re_compile_pattern(p: *const c_char, len: usize, b: *mut RePatternBuffer) -> *const c_char;
    #[link_name = "re_compile_fastmap"]
    fn host_re_compile_fastmap(b: *mut RePatternBuffer) -> c_int;
    #[link_name = "re_search"]
    fn host_re_search(b: *mut RePatternBuffer, s: *const c_char, len: i32, start: i32, range: i32, regs: *mut ReRegisters) -> i32;
    #[link_name = "re_match"]
    fn host_re_match(b: *mut RePatternBuffer, s: *const c_char, len: i32, start: i32, regs: *mut ReRegisters) -> i32;
    #[link_name = "re_search_2"]
    fn host_re_search_2(b: *mut RePatternBuffer, s1: *const c_char, l1: i32, s2: *const c_char, l2: i32, start: i32, range: i32, regs: *mut ReRegisters, stop: i32) -> i32;
    #[link_name = "re_match_2"]
    fn host_re_match_2(b: *mut RePatternBuffer, s1: *const c_char, l1: i32, s2: *const c_char, l2: i32, start: i32, regs: *mut ReRegisters, stop: i32) -> i32;
    #[link_name = "re_set_registers"]
    fn host_re_set_registers(b: *mut RePatternBuffer, regs: *mut ReRegisters, n: u32, starts: *mut i32, ends: *mut i32);
    #[link_name = "re_comp"]
    fn host_re_comp(s: *const c_char) -> *const c_char;
    #[link_name = "re_exec"]
    fn host_re_exec(s: *const c_char) -> c_int;
}

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

fn zero_re() -> RegexT {
    RegexT { buffer: core::ptr::null_mut(), allocated: 0, used: 0, syntax: 0, fastmap: core::ptr::null_mut(), translate: core::ptr::null_mut(), re_nsub: 0, bits: 0, _pad: 0 }
}

#[derive(Debug, PartialEq, Clone)]
struct Outcome {
    comp: i32,
    errtext: Vec<u8>,
    nsub: usize,
    bits: u32,
    syntax: u64,
    fastmap: Vec<u8>,
    exec: Option<i32>,
    pm: Vec<(i32, i32)>,
}

const SENT: i32 = -7777;

fn errtext(f: unsafe extern "C" fn(c_int, *const RegexT, *mut c_char, usize) -> usize, code: i32, re: *const RegexT) -> Vec<u8> {
    let mut buf = vec![0u8; 200];
    let n = unsafe { f(code, re, buf.as_mut_ptr().cast(), buf.len()) };
    assert!(n <= 200);
    buf.truncate(n.saturating_sub(1));
    buf
}

#[derive(Clone)]
struct Case {
    pat: Vec<u8>,
    cflags: i32,
    text: Vec<u8>,
    eflags: i32,
    nmatch: usize,
    se: (i32, i32),
}

fn run(host: bool, c: &Case) -> Outcome {
    let mut re = zero_re();
    let cpat = std::ffi::CString::new(c.pat.clone()).unwrap();
    let mut o = Outcome { comp: 0, errtext: vec![], nsub: 0, bits: 0, syntax: 0, fastmap: vec![], exec: None, pm: vec![] };
    unsafe {
        o.comp = if host { host_regcomp(&mut re, cpat.as_ptr(), c.cflags) } else { regcomp(&mut re, cpat.as_ptr(), c.cflags) };
        if o.comp != 0 {
            o.errtext = if host { errtext(host_regerror, o.comp, &re) } else { errtext(regerror, o.comp, &re) };
            return o;
        }
        o.nsub = re.re_nsub;
        o.bits = re.bits;
        o.syntax = re.syntax as u64;
        o.fastmap = std::slice::from_raw_parts(re.fastmap.cast::<u8>(), 256).to_vec();
        let mut ctext = c.text.clone();
        ctext.push(0);
        let n = c.nmatch.max(1);
        let mut pm = vec![RegMatch { so: SENT, eo: SENT }; n];
        if c.eflags & REG_STARTEND != 0 {
            pm[0] = RegMatch { so: c.se.0, eo: c.se.1 };
        }
        let r = if host {
            host_regexec(&re, ctext.as_ptr().cast(), c.nmatch, pm.as_mut_ptr(), c.eflags)
        } else {
            regexec(&re, ctext.as_ptr().cast(), c.nmatch, pm.as_mut_ptr(), c.eflags)
        };
        o.exec = Some(r);
        o.pm = pm.iter().map(|m| (m.so, m.eo)).collect();
        if host {
            host_regfree(&mut re);
        } else {
            regfree(&mut re);
        }
    }
    o
}

static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The lock of the tests that compare with the host or change the locale. It also refreshes the host's per-thread ctype
/// caches: glibc fills them (`__libc_tsd_CTYPE_B` ..., what `isctype` and so regcomp's classes read) when a thread starts and
/// updates them in setlocale for the calling thread only (locale/lc-ctype.c `_nl_postload_ctype`). A test thread started
/// while another test had, say, en_US.ISO-8859-1 in force kept that table after the locale went back to "C", and its host
/// regcomp then put 0x80-0x9f into `[[:cntrl:]]` (FIXLIST #96: rxspencer_vectors failed about 1 run in 3).
/// `uselocale(LC_GLOBAL_LOCALE)` reloads them from the global locale in force.
fn lock() -> std::sync::MutexGuard<'static, ()> {
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // (LC_GLOBAL_LOCALE is (locale_t) -1)
    unsafe { libc::uselocale(-1isize as libc::locale_t) };
    g
}

fn ser(o: &Outcome) -> Vec<u8> {
    let mut b = vec![];
    b.extend_from_slice(&o.comp.to_le_bytes());
    b.extend_from_slice(&(o.errtext.len() as u32).to_le_bytes());
    b.extend_from_slice(&o.errtext);
    b.extend_from_slice(&(o.nsub as u64).to_le_bytes());
    b.extend_from_slice(&o.bits.to_le_bytes());
    b.extend_from_slice(&o.syntax.to_le_bytes());
    b.extend_from_slice(&(o.fastmap.len() as u32).to_le_bytes());
    b.extend_from_slice(&o.fastmap);
    match o.exec {
        None => b.push(0),
        Some(v) => {
            b.push(1);
            b.extend_from_slice(&v.to_le_bytes());
        }
    }
    b.extend_from_slice(&(o.pm.len() as u32).to_le_bytes());
    for (s, e) in &o.pm {
        b.extend_from_slice(&s.to_le_bytes());
        b.extend_from_slice(&e.to_le_bytes());
    }
    b
}

fn deser(b: &[u8]) -> Outcome {
    let mut p = 0;
    let mut take = |n: usize| {
        let s = &b[p..p + n];
        p += n;
        s.to_vec()
    };
    let i32_ = |v: Vec<u8>| i32::from_le_bytes(v.try_into().unwrap());
    let u32_ = |v: Vec<u8>| u32::from_le_bytes(v.try_into().unwrap());
    let u64_ = |v: Vec<u8>| u64::from_le_bytes(v.try_into().unwrap());
    let comp = i32_(take(4));
    let n = u32_(take(4)) as usize;
    let errtext = take(n);
    let nsub = u64_(take(8)) as usize;
    let bits = u32_(take(4));
    let syntax = u64_(take(8));
    let n = u32_(take(4)) as usize;
    let fastmap = take(n);
    let exec = if take(1)[0] == 0 { None } else { Some(i32_(take(4))) };
    let n = u32_(take(4)) as usize;
    let mut pm = vec![];
    for _ in 0..n {
        let s = i32_(take(4));
        let e = i32_(take(4));
        pm.push((s, e));
    }
    Outcome { comp, errtext, nsub, bits, syntax, fastmap, exec, pm }
}

/// glibc crashes (stack overflow in check_dst_limits_calc_pos_1) or loops on some patterns, so
/// the host always runs in a forked child with a 2 s alarm; None when the child died.
fn run_host(c: &Case) -> Option<Outcome> {
    unsafe {
        let mut fds = [0 as c_int; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        if pid == 0 {
            libc::close(fds[0]);
            libc::alarm(1);
            let o = run(true, c);
            let b = ser(&o);
            let mut off = 0;
            while off < b.len() {
                let n = libc::write(fds[1], b.as_ptr().add(off).cast(), b.len() - off);
                if n <= 0 {
                    libc::_exit(3);
                }
                off += n as usize;
            }
            libc::_exit(0);
        }
        libc::close(fds[1]);
        let mut buf = vec![];
        let mut chunk = [0u8; 4096];
        loop {
            let n = libc::read(fds[0], chunk.as_mut_ptr().cast(), chunk.len());
            if n <= 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n as usize]);
        }
        libc::close(fds[0]);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0 && !buf.is_empty() { Some(deser(&buf)) } else { None }
    }
}

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).escape_debug().to_string()
}

fn fdesc(o: &Outcome) -> String {
    format!("comp {} err {:?} nsub {} bits {:#x} syntax {:#x} exec {:?} pm {:?}", o.comp, show(&o.errtext), o.nsub, o.bits, o.syntax, o.exec, o.pm)
}

fn compare(c: &Case) -> Option<String> {
    let h = match run_host(c) {
        Some(h) => h,
        None => {
            HOST_CRASHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
    };
    let t0 = std::time::Instant::now();
    let m = run(false, c);
    if m.comp == REG_ESPACE && h.comp == 0 {
        // the closure tables of some anchor-heavy patterns exceed 1 MiB, which the allocator used
        // by the host tests (rusty-libc-malloc, no-brk) refuses; counted and reported, never hidden
        ESPACE_SKIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    if t0.elapsed().as_millis() > 1500 {
        eprintln!("SLOW ours {} ms: pattern {:?} text {:?}", t0.elapsed().as_millis(), show(&c.pat), show(&c.text));
    }
    if h == m {
        return None;
    }
    let fm = if h.fastmap != m.fastmap {
        let d: Vec<usize> = (0..256.min(h.fastmap.len().min(m.fastmap.len()))).filter(|&i| h.fastmap[i] != m.fastmap[i]).collect();
        format!("\n   fastmap differs at {:?} (host ones {}, ours ones {})", &d[..d.len().min(8)], h.fastmap.iter().filter(|&&x| x != 0).count(), m.fastmap.iter().filter(|&&x| x != 0).count())
    } else {
        String::new()
    };
    Some(format!(
        "pattern {:?} cflags {} text {:?} eflags {} nmatch {} se {:?}\n   host: {}\n   ours: {}{}",
        show(&c.pat),
        c.cflags,
        show(&c.text),
        c.eflags,
        c.nmatch,
        c.se,
        fdesc(&h),
        fdesc(&m),
        fm
    ))
}

static ESPACE_SKIPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static HOST_CRASHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn has_bref(pat: &[u8]) -> bool {
    pat.windows(2).any(|w| w[0] == b'\\' && (b'1'..=b'9').contains(&w[1]))
}

/// Patterns with back-references are counted apart: glibc itself is wrong on some of them (it
/// reports groups with rm_eo == -1, misses matches that exist, crashes or loops), so for those
/// only the rate of disagreement is checked, for all the others every case must be identical.
struct Report {
    n: usize,
    bad: Vec<String>,
    count: usize,
    bn: usize,
    bcount: usize,
    bbad: Vec<String>,
}

impl Report {
    fn new() -> Report {
        Report { n: 0, bad: vec![], count: 0, bn: 0, bcount: 0, bbad: vec![] }
    }
    fn check(&mut self, c: &Case) {
        if std::env::var_os("RX_TRACE").is_some() {
            eprintln!("CASE {:?} cf {} text {:?} ef {} nm {}", show(&c.pat), c.cflags, show(&c.text), c.eflags, c.nmatch);
        }
        let b = has_bref(&c.pat);
        if b {
            self.bn += 1;
        } else {
            self.n += 1;
        }
        if let Some(m) = compare(c) {
            if b {
                self.bcount += 1;
                if self.bbad.len() < 6 {
                    self.bbad.push(m);
                }
            } else {
                self.count += 1;
                if self.bad.len() < std::env::var("RX_MAXBAD").ok().and_then(|v| v.parse().ok()).unwrap_or(12) {
                    self.bad.push(m);
                }
            }
        }
    }
    fn finish(self, what: &str) {
        eprintln!(
            "{what}: {} cases without back-references, {} differences; {} with back-references, {} differences (glibc crashed or hung on {}, ours out of memory on {} so far)",
            self.n,
            self.count,
            self.bn,
            self.bcount,
            HOST_CRASHES.load(std::sync::atomic::Ordering::Relaxed),
            ESPACE_SKIPS.load(std::sync::atomic::Ordering::Relaxed)
        );
        if std::env::var_os("RX_SHOWBREF").is_some() {
            eprintln!("back-reference differences:\n{}", self.bbad.join("\n"));
        }
        if self.count > 0 {
            panic!("{what}: {} of {} cases differ from glibc; first:\n{}", self.count, self.n, self.bad.join("\n"));
        }
        if self.bn > 0 && self.bcount * 100 > self.bn * 12 {
            panic!("{what}: back-reference cases differ too often ({} of {}); first:\n{}", self.bcount, self.bn, self.bbad.join("\n"));
        }
    }
}

fn case(pat: &[u8], cflags: i32, text: &[u8], eflags: i32, nmatch: usize) -> Case {
    Case { pat: pat.to_vec(), cflags, text: text.to_vec(), eflags, nmatch, se: (0, text.len() as i32) }
}

// ---------------------------------------------------------------- random generation

struct Piece {
    ere: Vec<u8>,
    bre: Vec<u8>,
    sample: Vec<u8>,
}

struct Gen {
    r: Rng,
    groups: Vec<Option<Vec<u8>>>,
}

const ALPHA: &[u8] = b"abcABC01 _-";
const RANDCH: &[u8] = b"abcABC01 _-\n.,:;";

impl Gen {
    fn ch(&mut self) -> u8 {
        if self.r.chance(4) { b'\n' } else { *self.r.pick(ALPHA) }
    }

    fn atom(&mut self, depth: usize) -> Piece {
        let k = self.r.below(100);
        let mut p = Piece { ere: vec![], bre: vec![], sample: vec![] };
        if k < 30 {
            let c = self.ch();
            p.ere.push(c);
            p.bre.push(c);
            p.sample.push(c);
        } else if k < 38 {
            p.ere.push(b'.');
            p.bre.push(b'.');
            p.sample.push(self.ch());
        } else if k < 52 {
            let items: [(&[u8], &[u8]); 16] = [
                (b"[abc]", b"b"),
                (b"[^a]", b"c"),
                (b"[a-c]", b"c"),
                (b"[[:alpha:]]", b"A"),
                (b"[[:digit:]_]", b"1"),
                (b"[]a]", b"]"),
                (b"[a-]", b"-"),
                (b"[[:upper:]]", b"B"),
                (b"[^[:space:]]", b"a"),
                (b"[[.a.]]", b"a"),
                (b"[[=a=]b]", b"a"),
                (b"[[:lower:][:digit:]]", b"0"),
                (b"[^]a]", b"b"),
                (b"[a-cA-C]", b"B"),
                (b"[[:blank:]]", b" "),
                (b"[\n]", b"\n"),
            ];
            let (s, smp) = *self.r.pick(&items);
            p.ere.extend_from_slice(s);
            p.bre.extend_from_slice(s);
            p.sample.extend_from_slice(smp);
        } else if k < 60 {
            let items: [(&[u8], &[u8]); 4] = [(b"\\w", b"a"), (b"\\W", b" "), (b"\\s", b" "), (b"\\S", b"b")];
            let (s, smp) = *self.r.pick(&items);
            p.ere.extend_from_slice(s);
            p.bre.extend_from_slice(s);
            p.sample.extend_from_slice(smp);
        } else if k < 70 {
            let items: [&[u8]; 8] = [b"\\b", b"\\B", b"\\<", b"\\>", b"\\`", b"\\'", b"^", b"$"];
            let s = *self.r.pick(&items);
            p.ere.extend_from_slice(s);
            p.bre.extend_from_slice(s);
        } else if k < 90 && depth < 4 {
            let idx = self.groups.len();
            self.groups.push(None);
            let inner = self.alt(depth + 1);
            self.groups[idx] = Some(inner.sample.clone());
            p.ere.push(b'(');
            p.ere.extend_from_slice(&inner.ere);
            p.ere.push(b')');
            p.bre.extend_from_slice(b"\\(");
            p.bre.extend_from_slice(&inner.bre);
            p.bre.extend_from_slice(b"\\)");
            p.sample = inner.sample;
        } else {
            let done: Vec<usize> = (0..self.groups.len()).filter(|&i| self.groups[i].is_some() && i < 9).collect();
            if done.is_empty() {
                let c = self.ch();
                p.ere.push(c);
                p.bre.push(c);
                p.sample.push(c);
            } else {
                let i = *self.r.pick(&done);
                let s = [b'\\', b'1' + i as u8];
                p.ere.extend_from_slice(&s);
                p.bre.extend_from_slice(&s);
                p.sample = self.groups[i].clone().unwrap();
            }
        }
        p
    }

    fn rep(&mut self, depth: usize) -> Piece {
        let mut a = self.atom(depth);
        if self.r.chance(45) {
            let k = self.r.below(7);
            let (e, b, lo, hi): (Vec<u8>, Vec<u8>, usize, usize) = match k {
                0 | 1 => (b"*".to_vec(), b"*".to_vec(), 0, 3),
                2 => (b"+".to_vec(), b"\\+".to_vec(), 1, 3),
                3 => (b"?".to_vec(), b"\\?".to_vec(), 0, 1),
                _ => {
                    let m = self.r.below(3);
                    let n = m + self.r.below(3);
                    match self.r.below(4) {
                        0 => (format!("{{{m}}}").into_bytes(), format!("\\{{{m}\\}}").into_bytes(), m, m),
                        1 => (format!("{{{m},}}").into_bytes(), format!("\\{{{m},\\}}").into_bytes(), m, m + 2),
                        2 => (format!("{{,{n}}}").into_bytes(), format!("\\{{,{n}\\}}").into_bytes(), 0, n),
                        _ => (format!("{{{m},{n}}}").into_bytes(), format!("\\{{{m},{n}\\}}").into_bytes(), m, n),
                    }
                }
            };
            let times = lo + if hi > lo { self.r.below(hi - lo + 1) } else { 0 };
            let one = a.sample.clone();
            a.sample.clear();
            for _ in 0..times {
                a.sample.extend_from_slice(&one);
            }
            a.ere.extend_from_slice(&e);
            a.bre.extend_from_slice(&b);
        }
        a
    }

    fn concat(&mut self, depth: usize) -> Piece {
        let n = 1 + self.r.below(4);
        let mut p = Piece { ere: vec![], bre: vec![], sample: vec![] };
        for _ in 0..n {
            let a = self.rep(depth);
            p.ere.extend_from_slice(&a.ere);
            p.bre.extend_from_slice(&a.bre);
            p.sample.extend_from_slice(&a.sample);
        }
        p
    }

    fn alt(&mut self, depth: usize) -> Piece {
        let mut p = self.concat(depth);
        while self.r.chance(22) {
            let q = self.concat(depth);
            p.ere.push(b'|');
            p.bre.extend_from_slice(b"\\|");
            p.ere.extend_from_slice(&q.ere);
            p.bre.extend_from_slice(&q.bre);
            if self.r.chance(50) {
                p.sample = q.sample;
            }
        }
        p
    }

    fn text_from(&mut self, sample: &[u8]) -> Vec<u8> {
        let mut t = sample.to_vec();
        if self.r.chance(50) {
            let n = self.r.below(3);
            let mut pre: Vec<u8> = (0..n).map(|_| *self.r.pick(RANDCH)).collect();
            pre.extend_from_slice(&t);
            t = pre;
        }
        if self.r.chance(50) {
            let n = self.r.below(3);
            for _ in 0..n {
                t.push(*self.r.pick(RANDCH));
            }
        }
        if self.r.chance(25) && !t.is_empty() {
            let i = self.r.below(t.len());
            match self.r.below(3) {
                0 => {
                    t.remove(i);
                }
                1 => t[i] = *self.r.pick(RANDCH),
                _ => t.insert(i, *self.r.pick(RANDCH)),
            }
        }
        if self.r.chance(8) {
            let n = self.r.below(10);
            t = (0..n).map(|_| *self.r.pick(RANDCH)).collect();
        }
        t
    }
}

fn gen_case(g: &mut Gen, force_flags: Option<i32>) -> Case {
    g.groups.clear();
    let p = g.alt(0);
    let ere = g.r.chance(50);
    let mut pat = if ere { p.ere } else { p.bre };
    if g.r.chance(7) {
        let specials = b"*+?{}()[]|\\^$.,-:=\n";
        let c = *g.r.pick(specials);
        let i = g.r.below(pat.len() + 1);
        pat.insert(i, c);
        if g.r.chance(30) {
            let c = *g.r.pick(specials);
            let i = g.r.below(pat.len() + 1);
            pat.insert(i, c);
        }
    }
    let text = g.text_from(&p.sample);
    let mut cflags = if ere { REG_EXTENDED } else { 0 };
    match force_flags {
        Some(f) => cflags |= f,
        None => {
            if g.r.chance(20) {
                cflags |= REG_ICASE;
            }
            if g.r.chance(25) {
                cflags |= REG_NEWLINE;
            }
            if g.r.chance(8) {
                cflags |= REG_NOSUB;
            }
        }
    }
    let mut eflags = 0;
    if g.r.chance(12) {
        eflags |= REG_NOTBOL;
    }
    if g.r.chance(12) {
        eflags |= REG_NOTEOL;
    }
    let mut se = (0, text.len() as i32);
    if g.r.chance(10) {
        eflags |= REG_STARTEND;
        let a = g.r.below(text.len() + 1);
        let b = a + g.r.below(text.len() - a + 1);
        se = (a as i32, b as i32);
    }
    let nmatch = *g.r.pick(&[0usize, 1, 2, 3, 5, 10, 10, 10, 12]);
    // with STARTEND the "string" is text[..end]
    Case { pat, cflags, text, eflags, nmatch, se }
}

fn random_run(seed: u64, n: usize, what: &str, flags: Option<i32>) {
    let _g = lock();
    let mut g = Gen { r: Rng(seed), groups: vec![] };
    let mut rep = Report::new();
    for _ in 0..n {
        let c = gen_case(&mut g, flags);
        rep.check(&c);
    }
    rep.finish(what);
}

/// As `random_run`, with every text padded to well over the DFA's threshold: junk before and after
/// the text the generator made (and no REG_STARTEND, which would index the unpadded text).
fn random_run_long(seed: u64, n: usize, what: &str, flags: Option<i32>) {
    let _g = lock();
    let mut g = Gen { r: Rng(seed), groups: vec![] };
    let mut rep = Report::new();
    for _ in 0..n {
        let mut c = gen_case(&mut g, flags);
        let junk = |g: &mut Gen, len: usize| -> Vec<u8> {
            // some junk is made of a few letters so that partial matches are common
            let small = g.r.chance(50);
            (0..len).map(|_| if small { b"abc "[g.r.below(4)] } else { *g.r.pick(RANDCH) }).collect()
        };
        let (pl, sl) = (g.r.below(300), g.r.below(100) + if g.r.chance(50) { 64 } else { 0 });
        let mut t = junk(&mut g, pl);
        t.extend_from_slice(&c.text);
        t.extend(junk(&mut g, sl));
        if t.len() < 64 {
            t.extend(std::iter::repeat_n(b'z', 64 - t.len()));
        }
        c.text = t;
        c.eflags &= !REG_STARTEND;
        rep.check(&c);
    }
    rep.finish(what);
}

#[test]
fn random_patterns_long_texts() {
    random_run_long(0x5eed_0001_dead_1111, n_cases() / 2, "random patterns, long texts, random flags", None);
}

#[test]
fn random_patterns_long_texts_plain() {
    random_run_long(0x5eed_0002_beef_2222, n_cases() / 2, "random patterns, long texts, no cflags", Some(0));
}

#[test]
fn random_patterns_long_texts_newline() {
    random_run_long(0x5eed_0003_cafe_3333, n_cases() / 2, "random patterns, long texts, REG_NEWLINE", Some(REG_NEWLINE));
}

#[test]
fn random_patterns_long_texts_icase() {
    random_run_long(0x5eed_0004_f00d_4444, n_cases() / 2, "random patterns, long texts, REG_ICASE", Some(REG_ICASE));
}

/// One compiled pattern, many texts: the DFA keeps its states between searches, so this exercises the
/// cache (transitions built on earlier texts, states shared by different texts, the switch to the DFA
/// after the first short searches) against fresh results from the host.
#[test]
fn compiled_pattern_reused_on_many_texts() {
    let _g = lock();
    crate::dfa::TEST_STATE_CAP.store(1200, std::sync::atomic::Ordering::Relaxed);
    reuse_run(0xc0ff_ee00_1234_5678);
}

/// The same with a state limit so small that the cache is thrown away again and again (and the DFA
/// switches itself off for a pattern that keeps overflowing).
#[test]
fn compiled_pattern_reused_with_tiny_state_limit() {
    let _g = lock();
    crate::dfa::TEST_STATE_CAP.store(5, std::sync::atomic::Ordering::Relaxed);
    reuse_run(0x0dd_ba11_5eed_0042);
    crate::dfa::TEST_STATE_CAP.store(1200, std::sync::atomic::Ordering::Relaxed);
}

fn reuse_run(seed: u64) {
    let mut g = Gen { r: Rng(seed), groups: vec![] };
    let (mut patterns, mut searches) = (0usize, 0usize);
    while patterns < 400 {
        let c = gen_case(&mut g, None);
        if has_bref(&c.pat) {
            continue;
        }
        let cpat = std::ffi::CString::new(c.pat.clone()).unwrap();
        let (mut ours, mut host) = (zero_re(), zero_re());
        let (a, b) = unsafe { (regcomp(&mut ours, cpat.as_ptr(), c.cflags), host_regcomp(&mut host, cpat.as_ptr(), c.cflags)) };
        if a != 0 || b != 0 {
            assert_eq!(a, b, "compile result of {:?}", show(&c.pat));
            continue;
        }
        patterns += 1;
        for k in 0..80 {
            let sample = g.text_from(&c.text);
            let mut t: Vec<u8> = (0..g.r.below(if k % 3 == 0 { 40 } else { 400 })).map(|_| if g.r.chance(70) { b"abc \n"[g.r.below(5)] } else { *g.r.pick(RANDCH) }).collect();
            t.extend_from_slice(&sample);
            t.extend((0..g.r.below(120)).map(|_| *g.r.pick(RANDCH)));
            t.push(0);
            let eflags = [0, 0, REG_NOTBOL, REG_NOTEOL][g.r.below(4)];
            let nm = [0usize, 1, 3][g.r.below(3)];
            let mut pa = vec![RegMatch { so: SENT, eo: SENT }; nm.max(1)];
            let mut pb = pa.clone();
            let (ra, rb) = unsafe { (regexec(&ours, t.as_ptr().cast(), nm, pa.as_mut_ptr(), eflags), host_regexec(&host, t.as_ptr().cast(), nm, pb.as_mut_ptr(), eflags)) };
            let same = ra == rb && pa.iter().zip(pb.iter()).all(|(x, y)| (x.so, x.eo) == (y.so, y.eo));
            assert!(same, "pattern {:?} cflags {} eflags {eflags} nmatch {nm} search {k} text {:?}: ours {ra} {:?} host {rb} {:?}", show(&c.pat), c.cflags, show(&t[..t.len() - 1]), pa.iter().map(|m| (m.so, m.eo)).collect::<Vec<_>>(), pb.iter().map(|m| (m.so, m.eo)).collect::<Vec<_>>());
            searches += 1;
        }
        unsafe {
            regfree(&mut ours);
            host_regfree(&mut host);
        }
    }
    eprintln!("reused patterns: {patterns} patterns, {searches} searches identical to glibc");
}

/// Cases per random test; RX_SCALE=n multiplies it (the default keeps the whole suite under a minute).
fn n_cases() -> usize {
    let scale: usize = std::env::var("RX_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    (if cfg!(debug_assertions) { 3000 } else { 24000 }) * scale
}

#[test]
fn random_patterns_default_flags() {
    random_run(0x1234_5678_9abc_def1, n_cases() / 4, "random patterns, random flags", None);
}

#[test]
fn random_patterns_plain() {
    random_run(0xfeed_f00d_dead_beef, n_cases() / 4, "random patterns, no cflags", Some(0));
}

#[test]
fn random_patterns_newline() {
    random_run(0x0bad_cafe_1357_2468, n_cases() / 4, "random patterns, REG_NEWLINE", Some(REG_NEWLINE));
}

#[test]
fn random_patterns_icase() {
    random_run(0x7777_1111_9999_3333, n_cases() / 4, "random patterns, REG_ICASE", Some(REG_ICASE));
}

// ---------------------------------------------------------------- fixed cases

#[test]
fn fixed_cases() {
    let _g = lock();
    let pats: &[(&str, i32)] = &[
        ("a", 1),
        ("a*", 1),
        ("(a*)*", 1),
        ("(a*)+", 1),
        ("(a|ab)(c|bcd)(d*)", 1),
        ("(a+|b)*", 1),
        ("(a*)(b*)(c*)", 1),
        ("((a)|(b))*", 1),
        ("(a?)*", 1),
        ("(a?)*b", 1),
        ("(a|b)*c|(a|ab)*c", 1),
        ("\\(a\\)\\1", 0),
        ("(a)\\1", 1),
        ("(.*)\\1", 1),
        ("^$", 1),
        ("^*", 0),
        ("a\\{2,3\\}", 0),
        ("a{2,3}", 1),
        ("x*", 1),
        ("\\bfoo\\b", 1),
        ("\\<w", 1),
        ("w\\>", 1),
        ("[[:alpha:]]+", 1),
        ("[a-c]*d", 1),
        ("(^|x)a", 1),
        ("a($|x)", 1),
        ("|a", 1),
        ("a|", 1),
        ("()", 1),
        ("(|a)+", 1),
        ("(a*)*b", 1),
        ("(a|b)*abb", 1),
        ("a**", 1),
        ("a\\|b", 0),
        ("\\(^a\\)", 0),
        ("a\\{1", 0),
        ("[[:foo:]]", 1),
        ("[b-a]", 1),
        ("\\(", 0),
        (")", 1),
        ("a{1,2}{3}", 1),
        ("(a{0,1}){0,2}", 1),
        ("((a)*)*", 1),
        ("(((a)))", 1),
        ("(a)|b", 1),
        ("a{0}b", 1),
        ("(a){0}b", 1),
        ("(a){2}", 1),
        ("(a){2,}", 1),
        ("(a){0,2}", 1),
        ("(a)?(b)?", 1),
    ];
    let texts: &[&str] = &["", "a", "aa", "aaa", "ab", "abcd", "abcdd", "b", "bb", "abb", "foo bar", "xa", "ax", "w w", "a\nb", "abab", "aab", "abcabc", "xfoox"];
    let mut rep = Report::new();
    for (p, ere) in pats {
        for t in texts {
            for &(extra, ef) in &[(0, 0), (REG_NEWLINE, 0), (REG_ICASE, 0), (0, REG_NOTBOL), (0, REG_NOTEOL)] {
                let cf = if *ere == 1 { REG_EXTENDED } else { 0 } | extra;
                rep.check(&case(p.as_bytes(), cf, t.as_bytes(), ef, 10));
            }
        }
    }
    rep.finish("fixed cases");
}

// ---------------------------------------------------------------- glibc's own test files

fn replace_special(s: &str) -> Vec<u8> {
    s.bytes()
        .map(|b| match b {
            b'N' => b'\n',
            b'T' => b'\t',
            b'S' => b' ',
            b => b,
        })
        .collect()
}

fn glibc_re_syntax(p: &mut Vec<u8>) {
    let mut i = 0;
    while i + 7 <= p.len() {
        if &p[i..i + 3] == b"[[:" && (p[i + 3] == b'<' || p[i + 3] == b'>') && &p[i + 4..i + 7] == b":]]" {
            let c = p[i + 3];
            p.splice(i..i + 7, [b'\\', c]);
            i += 2;
        } else {
            i += 1;
        }
    }
}

#[test]
fn rxspencer_vectors() {
    let _g = lock();
    let data = include_str!("../testdata/rxspencer.tests");
    let mut rep = Report::new();
    let mut expected_ok = 0usize;
    let mut expected_total = 0usize;
    for line in data.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').filter(|s| !s.is_empty()).collect();
        if f.len() < 3 {
            continue;
        }
        let mut pat = if f[0] == "\"\"" { vec![] } else { f[0].bytes().collect::<Vec<u8>>() };
        let flags = f[1];
        let mut text = if f[2] == "\"\"" { vec![] } else { f[2].bytes().collect::<Vec<u8>>() };
        let mut cflags = REG_EXTENDED;
        let mut eflags = 0;
        let mut both = false;
        let mut cerr = false;
        let mut skip = false;
        for ch in flags.chars() {
            match ch {
                'b' => cflags &= !REG_EXTENDED,
                '&' => both = true,
                'C' => cerr = true,
                'i' => cflags |= REG_ICASE,
                's' => cflags |= REG_NOSUB,
                'n' => cflags |= REG_NEWLINE,
                '^' => eflags |= REG_NOTBOL,
                '$' => eflags |= REG_NOTEOL,
                'm' | 'p' | '#' => skip = true,
                _ => {}
            }
        }
        if skip {
            continue;
        }
        pat = replace_special(std::str::from_utf8(&pat).unwrap());
        glibc_re_syntax(&mut pat);
        if cerr {
            text = text.clone();
        } else {
            text = replace_special(std::str::from_utf8(&text).unwrap());
        }
        if text.contains(&b'Z') && !cerr {
            // 'Z' stands for NUL in the file; C strings cannot hold it, glibc's test maps it too
        }
        let mut variants = vec![cflags];
        if both {
            variants = vec![cflags, cflags & !REG_EXTENDED];
        }
        for cf in variants {
            if cerr {
                let c = case(&pat, cf, b"", 0, 10);
                rep.check(&c);
                continue;
            }
            let c = case(&pat, cf, &text, eflags, 10);
            rep.check(&c);
            // does our result agree with the expectation column too?
            let m = run(false, &c);
            expected_total += 1;
            let exp_match = f.len() > 3;
            let got_match = m.exec == Some(0);
            if f.len() <= 3 && !got_match || (exp_match && got_match && cf & REG_NOSUB == 0 && expectation_ok(&f, &text, &m.pm)) {
                expected_ok += 1;
            }
        }
    }
    eprintln!("rxspencer: {expected_ok} of {expected_total} runs agree with the expectation column");
    rep.finish("rxspencer vectors (vs host)");
}

fn expectation_ok(f: &[&str], text: &[u8], pm: &[(i32, i32)]) -> bool {
    let chk = |idx: usize, want: &str| -> bool {
        let (so, eo) = pm[idx];
        if want == "-" {
            return so == -1 && eo == -1;
        }
        if so == -1 || eo == -1 {
            return false;
        }
        let w = replace_special(want);
        if let Some(rest) = w.strip_prefix(b"@") {
            so == eo && text[so as usize..].starts_with(&rest[..rest.len().min(1).max(rest.len())])
        } else {
            text[so as usize..eo as usize] == w[..]
        }
    };
    if !chk(0, f[3]) {
        return false;
    }
    if f.len() > 4 {
        for (i, w) in f[4].split(',').enumerate() {
            if i + 1 >= pm.len() || !chk(i + 1, w) {
                return false;
            }
        }
    }
    true
}

fn frob_escapes(s: &str, pattern: bool) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b't' => {
                    out.push(b'\t');
                    i += 2;
                    continue;
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                    continue;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                    continue;
                }
                b'\\' | b'^' | b'{' | b'|' | b'}' if !pattern => {
                    out.push(b[i + 1]);
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

#[test]
fn boost_vectors() {
    let _g = lock();
    let data = include_str!("../testdata/BOOST.tests");
    let mut rep = Report::new();
    let mut flags = REG_EXTENDED;
    let mut eflags = 0;
    let mut expect_ok = 0usize;
    let mut expect_total = 0usize;
    for line in data.lines() {
        if line.starts_with(';') || line.is_empty() {
            continue;
        }
        if line.starts_with('-') {
            flags = if line.contains("REG_BASIC") { 0 } else { REG_EXTENDED };
            if line.contains("REG_ICASE") {
                flags |= REG_ICASE;
            }
            if line.contains("REG_NEWLINE") {
                flags |= REG_NEWLINE;
            }
            eflags = 0;
            if line.contains("REG_NOTBOL") {
                eflags |= REG_NOTBOL;
            }
            if line.contains("REG_NOTEOL") {
                eflags |= REG_NOTEOL;
            }
            continue;
        }
        let t = line.trim_start_matches([' ', '\t']);
        let Some(sp) = t.find([' ', '\t']) else { continue };
        let pattern = &t[..sp];
        let rest = t[sp..].trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            continue;
        }
        let (string, tail, bad): (Option<&str>, &str, bool);
        if let Some(r) = rest.strip_prefix('"') {
            let Some(q) = r.find('"') else { continue };
            string = Some(&r[..q]);
            tail = &r[q + 1..];
            bad = false;
        } else {
            let e = rest.find([' ', '\t']).unwrap_or(rest.len());
            if rest.starts_with('!') {
                string = None;
                bad = true;
                tail = "";
            } else if e == rest.len() {
                continue;
            } else {
                string = Some(&rest[..e]);
                tail = &rest[e + 1..];
                bad = false;
            }
        }
        let pat = frob_escapes(pattern, true);
        let text = string.map(|s| frob_escapes(s, false)).unwrap_or_default();
        let c = Case { pat, cflags: flags, text: text.clone(), eflags, nmatch: 20, se: (0, text.len() as i32) };
        rep.check(&c);
        let m = run(false, &c);
        expect_total += 1;
        if bad {
            if m.comp != 0 {
                expect_ok += 1;
            }
            continue;
        }
        if m.comp != 0 {
            continue;
        }
        let nums: Vec<i32> = tail.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        let mut pm = m.pm.clone();
        pm.resize(20, (-1, -1));
        if m.exec != Some(0) {
            pm = vec![(-1, -1); 20];
        }
        let mut good = true;
        for (i, ch) in nums.chunks(2).enumerate() {
            if ch.len() == 2 && i < 20 && pm[i] != (ch[0], ch[1]) {
                good = false;
                break;
            }
        }
        if good {
            expect_ok += 1;
        }
    }
    eprintln!("BOOST: {expect_ok} of {expect_total} agree with the expected offsets");
    rep.finish("BOOST vectors (vs host)");
}

#[test]
fn pcre_vectors() {
    let _g = lock();
    let data = include_str!("../testdata/PCRE.tests");
    let mut rep = Report::new();
    let mut pattern: Option<Vec<u8>> = None;
    let mut icase = false;
    for line in data.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            icase = false;
            pattern = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix('/') {
            let Some(p) = rest.rfind('/') else { continue };
            let flags = &rest[p + 1..];
            icase = flags == "i";
            pattern = if flags.is_empty() || flags == "i" { Some(rest.as_bytes()[..p].to_vec()) } else { None };
            continue;
        }
        if let Some(s) = line.strip_prefix("    ")
            && let Some(pat) = &pattern
        {
            let cf = REG_EXTENDED | if icase { REG_ICASE } else { 0 };
            rep.check(&case(pat, cf, s.as_bytes(), 0, 20));
        }
    }
    rep.finish("PCRE vectors (vs host)");
}

// ---------------------------------------------------------------- regerror, layout

#[test]
fn regerror_texts_and_truncation() {
    let _g = lock();
    unsafe {
        let re = zero_re();
        for code in 0..17 {
            for size in [0usize, 1, 2, 5, 10, 30, 100] {
                let mut a = vec![0x55u8; 128];
                let mut b = vec![0x55u8; 128];
                let ra = host_regerror(code, &re, a.as_mut_ptr().cast(), size);
                let rb = regerror(code, &re, b.as_mut_ptr().cast(), size);
                assert_eq!(ra, rb, "code {code} size {size}");
                assert_eq!(a, b, "code {code} size {size}");
            }
            let m = CStr::from_ptr(ERROR_MSGS[code as usize].as_ptr().cast());
            assert!(!m.to_bytes().is_empty());
        }
    }
}

#[test]
fn struct_layout() {
    let _g = lock();
    assert_eq!(core::mem::size_of::<RegexT>(), 64);
    assert_eq!(core::mem::align_of::<RegexT>(), 8);
    assert_eq!(core::mem::offset_of!(RegexT, re_nsub), 48);
    assert_eq!(core::mem::offset_of!(RegexT, syntax), 24);
    assert_eq!(core::mem::offset_of!(RegexT, bits), 56);
    assert_eq!(core::mem::size_of::<RegMatch>(), 8);
    assert_eq!(core::mem::size_of::<ReRegisters>(), 24);
}


// ---------------------------------------------------------------- the GNU interface

const B_NOT_BOL: u32 = 1 << 5;
const B_NOT_EOL: u32 = 1 << 6;

#[derive(Clone)]
struct GCase {
    pat: Vec<u8>,
    syntax: u64,
    text1: Vec<u8>,
    text2: Vec<u8>,
    kind: usize,
    start: i32,
    range: i32,
    stop: i32,
    want_regs: bool,
    fastmap: bool,
    compile_fm: bool,
    translate: Option<Vec<u8>>,
    not_bol: bool,
    not_eol: bool,
    preset: usize,
}

fn cstr_lossy(p: *const c_char) -> String {
    if p.is_null() { "NULL".to_string() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string() }
}

fn alloc_bytes(host: bool, n: usize) -> *mut u8 {
    unsafe { if host { libc::malloc(n) as *mut u8 } else { rusty_libc_malloc::malloc(n) as *mut u8 } }
}

fn free_ptr(host: bool, p: *mut u8) {
    unsafe {
        if host {
            libc::free(p.cast())
        } else {
            rusty_libc_malloc::free(p.cast())
        }
    }
}

fn gnu_run(host: bool, c: &GCase) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    unsafe {
        if host {
            host_re_set_syntax(c.syntax as c_ulong);
        } else {
            re_set_syntax(c.syntax as c_ulong);
        }
        let mut b = zero_re();
        if c.fastmap {
            b.fastmap = alloc_bytes(host, 256) as *mut c_char;
        }
        if let Some(t) = &c.translate {
            let p = alloc_bytes(host, 256);
            core::ptr::copy_nonoverlapping(t.as_ptr(), p, 256);
            b.translate = p;
        }
        let msg = if host { host_re_compile_pattern(c.pat.as_ptr().cast(), c.pat.len(), &mut b) } else { re_compile_pattern(c.pat.as_ptr().cast(), c.pat.len(), &mut b) };
        if !msg.is_null() {
            let _ = write!(out, "error {:?}", cstr_lossy(msg));
            if host {
                host_regfree(&mut b);
            } else {
                regfree(&mut b);
            }
            return out;
        }
        let _ = write!(out, "nsub {} bits {:#x} syntax {:#x}; ", b.re_nsub, b.bits, b.syntax);
        if c.compile_fm && c.fastmap {
            let r = if host { host_re_compile_fastmap(&mut b) } else { re_compile_fastmap(&mut b) };
            let fm = std::slice::from_raw_parts(b.fastmap.cast::<u8>(), 256);
            let _ = write!(out, "fastmap r {} bits {:#x} ones {} h {}; ", r, b.bits, fm.iter().filter(|&&x| x != 0).count(), fm.iter().enumerate().fold(0u64, |a, (i, &x)| a.wrapping_mul(31).wrapping_add(x as u64 * (i as u64 + 1))));
        }
        if c.not_bol {
            b.bits |= B_NOT_BOL;
        }
        if c.not_eol {
            b.bits |= B_NOT_EOL;
        }
        let mut regs = ReRegisters { num_regs: 0, start: core::ptr::null_mut(), end: core::ptr::null_mut() };
        if c.preset > 0 {
            let starts = alloc_bytes(host, c.preset * 4) as *mut i32;
            let ends = alloc_bytes(host, c.preset * 4) as *mut i32;
            for i in 0..c.preset {
                *starts.add(i) = -5;
                *ends.add(i) = -5;
            }
            if host {
                host_re_set_registers(&mut b, &mut regs, c.preset as u32, starts, ends);
            } else {
                re_set_registers(&mut b, &mut regs, c.preset as u32, starts, ends);
            }
        }
        for round in 0..2 {
            let rp: *mut ReRegisters = if c.want_regs { &mut regs } else { core::ptr::null_mut() };
            let start = c.start + round;
            let r = match (c.kind, host) {
                (0, true) => host_re_search(&mut b, c.text1.as_ptr().cast(), c.text1.len() as i32, start, c.range, rp),
                (0, false) => re_search(&mut b, c.text1.as_ptr().cast(), c.text1.len() as i32, start, c.range, rp),
                (1, true) => host_re_match(&mut b, c.text1.as_ptr().cast(), c.text1.len() as i32, start, rp),
                (1, false) => re_match(&mut b, c.text1.as_ptr().cast(), c.text1.len() as i32, start, rp),
                (2, true) => host_re_search_2(&mut b, c.text1.as_ptr().cast(), c.text1.len() as i32, c.text2.as_ptr().cast(), c.text2.len() as i32, start, c.range, rp, c.stop),
                (2, false) => re_search_2(&mut b, c.text1.as_ptr().cast(), c.text1.len() as i32, c.text2.as_ptr().cast(), c.text2.len() as i32, start, c.range, rp, c.stop),
                (_, true) => host_re_match_2(&mut b, c.text1.as_ptr().cast(), c.text1.len() as i32, c.text2.as_ptr().cast(), c.text2.len() as i32, start, rp, c.stop),
                (_, false) => re_match_2(&mut b, c.text1.as_ptr().cast(), c.text1.len() as i32, c.text2.as_ptr().cast(), c.text2.len() as i32, start, rp, c.stop),
            };
            let _ = write!(out, "[r {} alloc {}", r, (b.bits >> 1) & 3);
            if c.want_regs && !regs.start.is_null() {
                let _ = write!(out, " n {}:", regs.num_regs);
                for i in 0..(regs.num_regs as usize).min(40) {
                    let _ = write!(out, " {},{}", *regs.start.add(i), *regs.end.add(i));
                }
            }
            out.push_str("] ");
        }
        if !regs.start.is_null() {
            free_ptr(host, regs.start.cast());
            free_ptr(host, regs.end.cast());
        }
        if host {
            host_regfree(&mut b);
        } else {
            regfree(&mut b);
        }
    }
    out
}

fn in_child(f: impl FnOnce() -> String) -> Option<String> {
    unsafe {
        let mut fds = [0 as c_int; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        if pid == 0 {
            libc::close(fds[0]);
            libc::alarm(1);
            let o = f();
            let b = o.as_bytes();
            let mut off = 0;
            while off < b.len() {
                let n = libc::write(fds[1], b.as_ptr().add(off).cast(), b.len() - off);
                if n <= 0 {
                    libc::_exit(3);
                }
                off += n as usize;
            }
            libc::_exit(0);
        }
        libc::close(fds[1]);
        let mut buf = vec![];
        let mut chunk = [0u8; 4096];
        loop {
            let n = libc::read(fds[0], chunk.as_mut_ptr().cast(), chunk.len());
            if n <= 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n as usize]);
        }
        libc::close(fds[0]);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0 && !buf.is_empty() { Some(String::from_utf8_lossy(&buf).to_string()) } else { None }
    }
}

fn gnu_compare(c: &GCase) -> Result<Option<String>, ()> {
    let host = in_child(|| gnu_run(true, c));
    let host = match host {
        Some(h) => h,
        None => return Err(()),
    };
    let ours = gnu_run(false, c);
    if host == ours {
        return Ok(None);
    }
    Ok(Some(format!(
        "pattern {:?} syntax {:#x} t1 {:?} t2 {:?} kind {} start {} range {} stop {} regs {} fm {}/{} notbol {} noteol {} preset {} translate {}\n   host: {}\n   ours: {}",
        show(&c.pat),
        c.syntax,
        show(&c.text1),
        show(&c.text2),
        c.kind,
        c.start,
        c.range,
        c.stop,
        c.want_regs,
        c.fastmap,
        c.compile_fm,
        c.not_bol,
        c.not_eol,
        c.preset,
        c.translate.is_some(),
        host,
        ours
    )))
}

const SYNTAXES: &[u64] = &[
    RE_SYNTAX_EMACS,
    RE_SYNTAX_AWK,
    RE_SYNTAX_GNU_AWK,
    RE_SYNTAX_POSIX_AWK,
    RE_SYNTAX_GREP,
    RE_SYNTAX_EGREP,
    RE_SYNTAX_POSIX_EGREP,
    RE_SYNTAX_POSIX_BASIC,
    RE_SYNTAX_POSIX_MINIMAL_BASIC,
    RE_SYNTAX_POSIX_EXTENDED,
    RE_SYNTAX_POSIX_MINIMAL_EXTENDED,
];

fn gen_gnu_case(g: &mut Gen) -> GCase {
    g.groups.clear();
    let p = g.alt(0);
    let mut syntax = *g.r.pick(SYNTAXES);
    if g.r.chance(15) {
        syntax |= RE_ICASE;
    }
    if g.r.chance(8) {
        syntax |= RE_NO_SUB;
    }
    if g.r.chance(12) {
        syntax ^= 1 << g.r.below(26);
    }
    let ere = syntax & RE_NO_BK_PARENS != 0;
    let mut pat = if ere { p.ere } else { p.bre };
    if g.r.chance(6) {
        let specials = b"*+?{}()[]|\\^$.,-:=\n";
        let c = *g.r.pick(specials);
        let i = g.r.below(pat.len() + 1);
        pat.insert(i, c);
    }
    let text = g.text_from(&p.sample);
    let split = g.r.below(text.len() + 1);
    let len = text.len() as i32;
    let kind = g.r.below(4);
    let two = kind >= 2;
    let (t1, t2) = if two { (text[..split].to_vec(), text[split..].to_vec()) } else { (text.clone(), vec![]) };
    let start = g.r.below(text.len() + 3) as i32 - 1;
    let range = g.r.below(2 * text.len() + 4) as i32 - len - 2;
    // stop beyond the length makes glibc read past the buffer, and below start it is not meaningful
    let lo = (start + 1).clamp(0, len) as usize;
    let stop = (lo + g.r.below(text.len() + 1 - lo)) as i32;
    let translate = if g.r.chance(10) {
        let mut t: Vec<u8> = (0..=255u8).collect();
        t[b'a' as usize] = b'b';
        t[b'B' as usize] = b'c';
        Some(t)
    } else {
        None
    };
    GCase {
        pat,
        syntax,
        text1: t1,
        text2: t2,
        kind,
        start,
        range,
        stop,
        want_regs: g.r.chance(80),
        fastmap: g.r.chance(60),
        compile_fm: g.r.chance(50),
        translate,
        not_bol: g.r.chance(10),
        not_eol: g.r.chance(10),
        preset: if g.r.chance(12) { 1 + g.r.below(4) } else { 0 },
    }
}

#[test]
fn gnu_interface_random() {
    let _g = lock();
    let n = n_cases() / 2;
    let mut g = Gen { r: Rng(0x4242_4242_1357_9bdf), groups: vec![] };
    let mut bad: Vec<String> = vec![];
    let (mut cnt, mut bcnt, mut bn, mut crashed) = (0usize, 0usize, 0usize, 0usize);
    let mut plain = 0usize;
    for _ in 0..n {
        let c = gen_gnu_case(&mut g);
        // back-references and user translate tables are counted apart (see the report)
        let b = has_bref(&c.pat) || c.translate.is_some();
        match gnu_compare(&c) {
            Err(()) => crashed += 1,
            Ok(None) => {
                if b {
                    bn += 1
                } else {
                    plain += 1
                }
            }
            Ok(Some(m)) => {
                if b {
                    bn += 1;
                    bcnt += 1;
                } else {
                    plain += 1;
                    cnt += 1;
                    if bad.len() < 15 {
                        bad.push(m);
                    }
                }
            }
        }
    }
    eprintln!("GNU interface: {plain} cases without back-references, {cnt} differences; {bn} with back-references, {bcnt} differences; glibc crashed on {crashed}");
    if cnt > 0 {
        panic!("GNU interface: {cnt} of {plain} cases differ from glibc; first:\n{}", bad.join("\n"));
    }
    assert!(bcnt * 100 <= bn.max(1) * 12, "too many back-reference differences: {bcnt} of {bn}");
}

#[test]
fn bsd_re_comp_exec() {
    let _g = lock();
    let mut g = Gen { r: Rng(0x1111_2222_3333_4444), groups: vec![] };
    let mut diffs = vec![];
    let mut n = 0;
    for _ in 0..400 {
        g.groups.clear();
        let p = g.alt(0);
        let syntax = *g.r.pick(&[RE_SYNTAX_EMACS, RE_SYNTAX_POSIX_BASIC, RE_SYNTAX_POSIX_EXTENDED, RE_SYNTAX_GREP]);
        let ere = syntax & RE_NO_BK_PARENS != 0;
        let pat = if ere { p.ere.clone() } else { p.bre.clone() };
        if has_bref(&pat) {
            continue;
        }
        let text = g.text_from(&p.sample);
        let cpat = std::ffi::CString::new(pat.clone()).unwrap();
        let ctext = std::ffi::CString::new(text.clone()).unwrap();
        unsafe {
            host_re_set_syntax(syntax as c_ulong);
            re_set_syntax(syntax as c_ulong);
            let hm = host_re_comp(cpat.as_ptr());
            let om = re_comp(cpat.as_ptr());
            let hs = cstr_lossy(hm);
            let os = cstr_lossy(om);
            let (he, oe) = if hm.is_null() { (host_re_exec(ctext.as_ptr()), re_exec(ctext.as_ptr())) } else { (-1, -1) };
            n += 1;
            if hs != os || he != oe {
                diffs.push(format!("re_comp {:?} syntax {syntax:#x} text {:?}: host ({hs}, {he}) ours ({os}, {oe})", show(&pat), show(&text)));
            }
        }
    }
    unsafe {
        // no pattern yet / NULL argument
        assert_eq!(cstr_lossy(host_re_comp(core::ptr::null())), cstr_lossy(re_comp(core::ptr::null())));
    }
    eprintln!("re_comp/re_exec: {n} cases, {} differences", diffs.len());
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
}

// ---------------------------------------------------------------- Rust API

#[test]
fn rust_api_basics() {
    let _g = lock();
    use crate::{Regex, Span};
    let re = Regex::new(b"(a+)(b*)c", REG_EXTENDED).unwrap();
    assert_eq!(re.group_count(), 2);
    assert!(re.is_match(b"xxaabbcxx"));
    assert!(!re.is_match(b"xxaabb"));
    assert_eq!(re.find(b"xxaabbcxx"), Some(Span { start: 2, end: 7 }));
    let mut caps = [None; 4];
    assert!(re.captures(b"xxaabbcxx", &mut caps));
    assert_eq!(caps[0], Some(Span { start: 2, end: 7 }));
    assert_eq!(caps[1], Some(Span { start: 2, end: 4 }));
    assert_eq!(caps[2], Some(Span { start: 4, end: 6 }));
    assert_eq!(caps[3], None);
    // the longest alternative wins, like POSIX says
    let re = Regex::new(b"a|ab|abc", REG_EXTENDED).unwrap();
    assert_eq!(re.find(b"zabcd"), Some(Span { start: 1, end: 4 }));
    // flags
    let re = Regex::new(b"^abc$", REG_EXTENDED | REG_ICASE | REG_NEWLINE).unwrap();
    assert!(re.is_match(b"x\nABC\ny"));
    let re = Regex::new(b"^abc", REG_EXTENDED).unwrap();
    let mut m = [crate::Reg { so: 0, eo: 0 }; 1];
    assert_eq!(re.exec(b"abc", 0, REG_NOTBOL, &mut m), Ok(false));
    assert_eq!(re.exec(b"abc", 0, 0, &mut m), Ok(true));
    // errors carry glibc's text
    let e = Regex::new(b"a\\{1", 0).unwrap_err();
    assert_eq!(e.0, REG_EBRACE);
    assert_eq!(e.message(), "Unmatched \\{");
    assert_eq!(Regex::new(b"(", REG_EXTENDED).unwrap_err().message(), "Unmatched ( or \\(");
    assert!(Regex::new(b")", 0).is_ok());
    // GNU syntax
    let re = Regex::with_syntax(b"\\(foo\\|bar\\)\\+", RE_SYNTAX_POSIX_BASIC, false).unwrap();
    assert_eq!(re.find(b"xfoobarfoo!"), Some(Span { start: 1, end: 10 }));
    // find_at keeps the text before the start as context
    let re = Regex::new(b"\\<w", REG_EXTENDED).unwrap();
    assert_eq!(re.find_at(b"aw w", 1), Some(Span { start: 3, end: 4 }));
}

// ---------------------------------------------------------------- speed

fn time_it<F: FnMut() -> usize>(mut f: F) -> (f64, usize) {
    let t = std::time::Instant::now();
    let r = f();
    (t.elapsed().as_secs_f64() * 1000.0, r)
}

/// Compile once, search `text` `reps` times; returns (ms, checksum of match offsets).
fn bench_one(host: bool, pat: &[u8], cflags: i32, text: &[u8], reps: usize) -> (f64, usize) {
    let cpat = std::ffi::CString::new(pat).unwrap();
    let mut ctext = text.to_vec();
    ctext.push(0);
    unsafe {
        let mut re = zero_re();
        let r = if host { host_regcomp(&mut re, cpat.as_ptr(), cflags) } else { regcomp(&mut re, cpat.as_ptr(), cflags) };
        assert_eq!(r, 0);
        let out = time_it(|| {
            let mut sum = 0usize;
            let mut pm = [RegMatch { so: -1, eo: -1 }; 4];
            for _ in 0..reps {
                let r = if host {
                    host_regexec(&re, ctext.as_ptr().cast(), 4, pm.as_mut_ptr(), 0)
                } else {
                    regexec(&re, ctext.as_ptr().cast(), 4, pm.as_mut_ptr(), 0)
                };
                sum = sum.wrapping_add(r as usize).wrapping_add(pm[0].so as usize).wrapping_add((pm[0].eo as usize).wrapping_mul(7)).wrapping_add((pm[1].so as usize).wrapping_mul(13));
            }
            sum
        });
        if host {
            host_regfree(&mut re);
        } else {
            regfree(&mut re);
        }
        out
    }
}

#[test]
fn speed_against_glibc() {
    let _g = lock();
    let mut rng = Rng(0xabcdef0123456789);
    let big: usize = if cfg!(debug_assertions) { 1 << 16 } else { 1 << 20 };
    let words: Vec<u8> = (0..big).map(|_| b"abcdefghij klmnop\n"[rng.below(18)]).collect();
    let mut with_match = words.clone();
    with_match.extend_from_slice(b" hello1234 tail");
    let a_run: Vec<u8> = vec![b'a'; if cfg!(debug_assertions) { 2000 } else { 20000 }];
    let mut a_run_b = a_run.clone();
    a_run_b.push(b'b');
    let ab: Vec<u8> = b"ab".iter().cycle().take(if cfg!(debug_assertions) { 2000 } else { 20000 }).copied().collect();
    type Bench<'a> = (&'a str, &'a [u8], i32, Vec<u8>, usize);
    let cases: Vec<Bench> = vec![
        ("(a*)*b, a^n (no b)", b"(a*)*b", REG_EXTENDED, a_run.clone(), 1),
        ("(a*)*b, a^n b", b"(a*)*b", REG_EXTENDED, a_run_b.clone(), 1),
        ("(a|aa)+$, a^n b", b"(a|aa)+$", REG_EXTENDED, a_run_b.clone(), 1),
        ("(a+)+c, a^n", b"(a+)+c", REG_EXTENDED, a_run.clone(), 1),
        ("(ab|a)(bc|c)?, (ab)^n", b"(ab|a)(bc|c)?", REG_EXTENDED, ab.clone(), 1),
        ("literal in 1 MB, match at end", b"hello[0-9]+", REG_EXTENDED, with_match.clone(), 1),
        ("no match in 1 MB (class)", b"[xyz]+q", REG_EXTENDED, words.clone(), 1),
        ("alternation in 1 MB, match at end", b"(foo|bar|hello)[0-9]{2,4}", REG_EXTENDED, with_match.clone(), 1),
        (".*x.*y.* in 1 MB", b".*x.*y.*", REG_EXTENDED | REG_NEWLINE, words.clone(), 1),
        ("short regexec x 200000", b"([a-z]+) ([0-9]+)", REG_EXTENDED, b"hello world 12345 end".to_vec(), if cfg!(debug_assertions) { 2000 } else { 200000 }),
        ("short literal regexec x 200000", b"world", REG_EXTENDED, b"hello world 12345 end".to_vec(), if cfg!(debug_assertions) { 2000 } else { 200000 }),
        ("short literal at start x 200000", b"hello", 0, b"hello world 12345 end".to_vec(), if cfg!(debug_assertions) { 2000 } else { 200000 }),
        ("short literal miss x 200000", b"xyzzy", REG_EXTENDED, b"hello world 12345 end".to_vec(), if cfg!(debug_assertions) { 2000 } else { 200000 }),
        ("short anchored literal x 200000", b"^hello", REG_EXTENDED, b"hello world 12345 end".to_vec(), if cfg!(debug_assertions) { 2000 } else { 200000 }),
    ];
    eprintln!("{:<40} {:>12} {:>12} {:>8}", "case", "glibc ms", "ours ms", "ratio");
    for (name, pat, cf, text, reps) in cases {
        let (hm, hs) = bench_one(true, pat, cf, &text, reps);
        let (om, os) = bench_one(false, pat, cf, &text, reps);
        eprintln!("{:<40} {:>12.2} {:>12.2} {:>8.2}", name, hm, om, om / hm.max(0.001));
        assert_eq!(hs, os, "{name}: results differ from glibc");
        assert!(om < 20000.0, "{name}: too slow ({om} ms)");
    }
}

#[test]
fn compile_does_not_leak_or_exhaust() {
    let _g = lock();
    // the same few patterns many times: memory use must stay flat (every compile ends in regfree)
    let pats: [&[u8]; 3] = [b"(\\b|\\W{,3})*|.A{1,2}", b"((a|b){1,20}c)*d", b"x{1,300}[[:alpha:]]+"];
    for i in 0..20000 {
        let p = pats[i % 3];
        let re = crate::Regex::new(p, REG_EXTENDED | REG_ICASE).unwrap_or_else(|e| panic!("compile of {:?} (iteration {i}): {e}", show(p)));
        assert!(re.group_count() <= 2);
    }
}

// ---- bracket ranges follow the collation sequence of the locale ----

/// Sets LC_ALL on the host and on our side; restores "C" on drop.
struct LocaleGuard;

impl LocaleGuard {
    fn set(name: &str) -> Option<LocaleGuard> {
        let c = std::ffi::CString::new(name).unwrap();
        unsafe {
            if libc::setlocale(libc::LC_ALL, c.as_ptr()).is_null() {
                return None;
            }
            let ours = rusty_libc_locale::setlocale(libc::LC_ALL, c.as_ptr());
            assert!(!ours.is_null(), "our setlocale({name}) failed but the host's worked");
        }
        Some(LocaleGuard)
    }
}

impl Drop for LocaleGuard {
    fn drop(&mut self) {
        unsafe {
            libc::setlocale(libc::LC_ALL, c"C".as_ptr());
            rusty_libc_locale::setlocale(libc::LC_ALL, c"C".as_ptr());
        }
    }
}

/// Which of the texts `texts` does pattern `pat` match (result, so, eo), and the compile result.
fn membership(host: bool, pat: &[u8], cflags: i32, texts: &[Vec<u8>]) -> (i32, Vec<(i32, i32, i32)>) {
    let mut re = zero_re();
    let cpat = std::ffi::CString::new(pat.to_vec()).unwrap();
    unsafe {
        let rc = if host { host_regcomp(&mut re, cpat.as_ptr(), cflags) } else { regcomp(&mut re, cpat.as_ptr(), cflags) };
        if rc != 0 {
            return (rc, vec![]);
        }
        let mut out = vec![];
        for t in texts {
            let mut ct = t.clone();
            ct.push(0);
            let mut pm = [RegMatch { so: SENT, eo: SENT }; 1];
            let r = if host { host_regexec(&re, ct.as_ptr().cast(), 1, pm.as_mut_ptr(), 0) } else { regexec(&re, ct.as_ptr().cast(), 1, pm.as_mut_ptr(), 0) };
            out.push((r, pm[0].so, pm[0].eo));
        }
        if host {
            host_regfree(&mut re);
        } else {
            regfree(&mut re);
        }
        (0, out)
    }
}

fn first_diff(a: &(i32, Vec<(i32, i32, i32)>), b: &(i32, Vec<(i32, i32, i32)>)) -> (i32, i32, Option<usize>) {
    (a.0, b.0, a.1.iter().zip(b.1.iter()).position(|(x, y)| x != y))
}

fn range_locales() -> Vec<&'static str> {
    vec![
        "C",
        "en_US.UTF-8",
        "de_DE.UTF-8",
        "sv_SE.UTF-8",
        "cs_CZ.UTF-8",
        "en_US.ISO-8859-1",
        "cs_CZ.ISO-8859-2",
        "da_DK.UTF-8",
        "et_EE.UTF-8",
        "hu_HU.UTF-8",
        "pl_PL.UTF-8",
        "fr_FR.UTF-8",
        "POSIX",
        "C.UTF-8",
    ]
}

fn run_range_checks(loc: &str, utf8: bool) {
    let Some(_lg) = LocaleGuard::set(loc) else {
        panic!("locale {loc} missing on this host");
    };
    // single-character texts: ASCII, and (single-byte charsets only) the upper half
    let mut texts: Vec<Vec<u8>> = (1u8..128).map(|b| vec![b]).collect();
    if !utf8 {
        texts.extend((128u8..=255).map(|b| vec![b]));
    }
    // REG_ICASE and character classes use the C locale only for bytes above 127 (a gap of the matcher): ASCII texts for them
    let tx = |cf: i32, p: &str| if cf & REG_ICASE != 0 || p.contains(":]") || p.contains("=]") { &texts[..127] } else { &texts[..] };
    let chars: Vec<u8> = (0x20u8..0x7f).collect();
    let mut n = 0usize;
    // every ASCII start and end, plain and negated, BRE and ERE
    // (a bracket in a UTF-8 locale takes a few milliseconds to compile: sample the pairs there)
    let step = if utf8 { 11 } else { 1 };
    for (xi, &x) in chars.iter().enumerate() {
        for (yi, &y) in chars.iter().enumerate() {
            if (xi + yi) % step != 0 && utf8 {
                continue;
            }
            if matches!(x, b'[' | b']' | b'\\' | b'^' | b'-') || matches!(y, b'[' | b']' | b'\\' | b'^' | b'-') {
                continue;
            }
            for pat in [format!("[{}-{}]", x as char, y as char), format!("[^{}-{}]", x as char, y as char)] {
                for cflags in [0, REG_EXTENDED | REG_ICASE] {
                    let h = membership(true, pat.as_bytes(), cflags, tx(cflags, &pat));
                    let o = membership(false, pat.as_bytes(), cflags, tx(cflags, &pat));
                    assert!(o == h, "locale {loc}: pattern {pat:?} cflags {cflags}: (ours, host, first differing text) {:?}", first_diff(&o, &h));
                    n += 1;
                }
            }
        }
    }
    // mixed expressions, collating symbols, endpoints that are special
    let pats: [&str; 40] = [
        "[a-z]", "[A-Z]", "[a-Z]", "[Z-a]", "[0-9a-f]", "[a-fA-F0-9]", "[[.a.]-z]", "[a-[.z.]]", "[[.a.]-[.f.]]", "[[.space.]-z]",
        "[[.hyphen.]]", "[[.-.]-0]", "[--/]", "[+--]", "[a-]", "[]-a]", "[]-]", "[^]-a]", "[[:alpha:]-z]", "[a-[:alpha:]]",
        "[a-z[:digit:]]", "[[:upper:]a-c]", "[b-a]", "[z-a]", "[ -~]", "[!-/:-@[-`{-~]", "[[.x.]-[.a.]]", "[[=a=]-z]", "[a-a]", "[A-a]",
        "[0-z]", "[ -/]", "[@-[]", "[{-~]", "[a-]]", "x[a-c]+y", "[a-c][d-f]", "^[a-m]*$", "[[:lower:]]", "[aA-zZ]",
    ];
    for p in pats {
        for cflags in [0, REG_EXTENDED, REG_EXTENDED | REG_ICASE] {
            let h = membership(true, p.as_bytes(), cflags, tx(cflags, p));
            let o = membership(false, p.as_bytes(), cflags, tx(cflags, p));
            assert!(o == h, "locale {loc}: pattern {p:?} cflags {cflags}: (ours, host, first differing text) {:?}", first_diff(&o, &h));
            n += 1;
        }
    }
    // longer texts through the same ranges
    let words: Vec<Vec<u8>> = ["hello World", "ZEBRA zebra", "abcXYZ123", "mnoMNO", "a-b_c", "Ab Ba Cb Zy", "zyxwvu ZYXWVU"].iter().map(|s| s.as_bytes().to_vec()).collect();
    for p in ["[a-z]+", "[A-Z]+", "[a-Z]+", "[b-y]+", "[B-Y]+", "[a-c]*[M-Z]", "([a-m]+)([N-Z]+)", "[^a-z]+", "[^A-Z]*"] {
        for cflags in [REG_EXTENDED, REG_EXTENDED | REG_ICASE] {
            let h = membership(true, p.as_bytes(), cflags, &words);
            let o = membership(false, p.as_bytes(), cflags, &words);
            assert!(o == h, "locale {loc}: pattern {p:?} cflags {cflags}: (ours, host, first differing text) {:?}", first_diff(&o, &h));
            n += 1;
        }
    }
    eprintln!("range checks in {loc}: {n} pattern/flag combinations identical to glibc");
}

#[test]
fn bracket_ranges_follow_locale_collation() {
    let _g = lock();
    for loc in range_locales() {
        run_range_checks(loc, loc.contains("UTF-8"));
    }
}


/// A spread of characters: all of the first blocks, then thinner, with the edges of every block size and plane.
fn char_sample() -> Vec<u32> {
    let mut v: Vec<u32> = (0..0x900).collect();
    v.extend((0x900..0x4000).step_by(3));
    v.extend((0x4000..0x30000).step_by(61));
    v.extend((0x30000..0x110000).step_by(97));
    for &e in &[0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xfffd, 0xffff, 0x10000, 0x1ffff, 0x20000, 0x2ffff, 0x30000, 0x323af, 0xe0001, 0xe01ef, 0xf0000, 0x10fffd, 0x10ffff] {
        v.push(e);
    }
    v.retain(|c| !(0xd800..=0xdfff).contains(c));
    v
}

#[test]
fn utf8_bracket_sets_from_tables_equal_the_scan_of_every_character() {
    let _g = lock();
    let pats: [&str; 32] = [
        "[[:alpha:]]", "[[:upper:]]", "[[:lower:]]", "[[:digit:]]", "[[:punct:]]", "[[:space:]]", "[[:alnum:]]", "[[:cntrl:]]", "[[:graph:]]",
        "[[:print:]]", "[[:blank:]]", "[[:xdigit:]]", "[^[:alpha:]]", "[^[:space:]]", "[a-z]", "[A-Z]", "[0-9a-f]", "[\u{e0}-\u{fc}]", "[[=e=]]",
        "[[=a=]]", "[^a]", "[^\u{e9}]", "\\w", "\\W", "\\s", "\\S", "[[:alpha:]\u{3b1}]", "[^\u{e9}-\u{fc}]", "[b-d\u{3b1}-\u{3c9}]",
        "[[=\u{e9}=]]", "[[.a.]-c]", "[ -~]",
    ];
    let chars = char_sample();
    let mut checked = 0u64;
    for loc in ["C.UTF-8", "en_US.UTF-8", "de_DE.UTF-8", "tr_TR.UTF-8", "cs_CZ.UTF-8", "ja_JP.UTF-8"] {
        let Some(_lg) = LocaleGuard::set(loc) else { panic!("locale {loc} missing on this host") };
        for cflags in [REG_EXTENDED, REG_EXTENDED | REG_ICASE] {
            for p in pats {
                let pat = p.to_string().into_bytes();
                crate::parse::FORCE_SCAN.store(false, core::sync::atomic::Ordering::Relaxed);
                let fast = crate::Regex::new(&pat, cflags);
                crate::parse::FORCE_SCAN.store(true, core::sync::atomic::Ordering::Relaxed);
                let slow = crate::Regex::new(&pat, cflags);
                crate::parse::FORCE_SCAN.store(false, core::sync::atomic::Ordering::Relaxed);
                let (fast, slow) = match (fast, slow) {
                    (Ok(a), Ok(b)) => (a, b),
                    (Err(a), Err(b)) => {
                        assert_eq!(a.0, b.0, "locale {loc} pattern {p:?} flags {cflags}: different errors");
                        continue;
                    }
                    (a, b) => panic!("locale {loc} pattern {p:?} flags {cflags}: one compiles, the other does not: {:?} {:?}", a.is_ok(), b.is_ok()),
                };
                for &c in &chars {
                    let mut buf = [0u8; 4];
                    let t = char::from_u32(c).unwrap().encode_utf8(&mut buf).as_bytes().to_vec();
                    let (a, b) = (fast.find(&t), slow.find(&t));
                    assert_eq!(a, b, "locale {loc} pattern {p:?} flags {cflags}: character U+{c:04X}");
                    checked += 1;
                }
            }
        }
    }
    eprintln!("{checked} (locale, pattern, flags, character) cells identical between the table walk and the scan");
}


include!("tests_coll.rs");

#[test]
fn utf8_compile_shortcuts_match_the_tables() {
    use crate::{charset, mbset};
    // (the lock: no other test changes the locale in between; the cache emptied: its 8 locale slots may be taken by the
    // locales of other tests, and then nothing is cached, by design; FIXLIST #96)
    let _g = lock();
    mbset::cased_clear();
    // the single-byte table of UTF-8 without decoding 256 bytes
    assert_eq!(charset::sb_chars(charset::Mb::Utf8), charset::sb_chars_decoded(charset::Mb::Utf8));
    // the table kept for REG_ICASE is what reading the mapping gives, and the same on the second ask
    let (mut pairs, mut kept) = (crate::vec::V::new(), crate::vec::V::new());
    mbset::cased_compute(&mut pairs, &mut kept);
    let c = mbset::cased_cached().expect("cached");
    assert_eq!(c.pairs, &pairs[..]);
    assert_eq!(c.kept, &kept[..]);
    let again = mbset::cased_cached().expect("cached");
    assert_eq!(again.pairs.as_ptr(), c.pairs.as_ptr());
}

/// FIXLIST #148: the automaton made from the charset's rows (`.`, negated sets, ranges in the EUC, GBK, BIG5, HKSCS and GB18030
/// locales) is node for node the one the trie of the characters found one by one gives (the sequences of `rows_seqs` and of
/// `collect_listed`, which asks the decoder about every character), for all characters and for sets of values.
#[test]
fn rows_canon_is_the_enumerated_automaton() {
    use crate::mbset;
    let _g = lock();
    let mut checked = 0;
    for loc in ["zh_TW.EUC-TW", "zh_CN.GBK", "zh_HK.big5hkscs", "zh_CN.gb18030", "ja_JP.eucJP", "ko_KR.eucKR", "zh_CN.GB2312", "zh_TW.big5"] {
        let Some(_l) = LocaleGuard::set(loc) else { continue };
        let mb = crate::charset::mb_kind();
        assert_eq!(mb, crate::charset::Mb::Other, "{loc}");
        // the single-byte characters from the decoder's body are the ones 256 decodes find (GBK's 0x80 is not one to `btowc`)
        let mut by_decode = crate::charset::sb_chars_decoded(mb);
        if loc.ends_with("GBK") {
            by_decode[2] &= !1;
        }
        assert_eq!(crate::charset::sb_chars(mb), by_decode, "{loc}: single bytes");
        // (GB18030's four-byte codes that are runs of one character are listed one by one in the enumeration; the rows path has them
        // among the runs, as ranges of values: the same characters, so they are left out here)
        let gb = loc.ends_with("gb18030");
        let enumerated = |pred: &mut dyn FnMut(u32) -> bool| {
            let mut seqs: crate::vec::V<mbset::Seq> = crate::vec::V::new();
            mbset::collect_listed(mb, false, 0x10ffff, &mut |wc, n| n > 1 && !(gb && n == 4) && pred(wc), &mut seqs);
            mbset::Canon::of_seqs(&seqs)
        };
        let all = enumerated(&mut |_| true);
        let rows = mbset::rows_canon(None).unwrap_or_else(|| panic!("{loc}: rows"));
        assert!(rows.same(&all), "{loc}: all characters");
        let mut seqs: crate::vec::V<mbset::Seq> = crate::vec::V::new();
        assert!(mbset::rows_seqs(None, &mut seqs));
        assert!(mbset::Canon::of_seqs(&seqs).same(&all), "{loc}: all characters as sequences");
        // sets of values: a few ranges, one character missing, many ranges, nothing
        let mut seed = 0x1234_5678u32;
        let mut rnd = move || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            seed >> 8
        };
        let mut sets: Vec<Vec<(u32, u32)>> = vec![vec![], vec![(0x80, 0x10ffff)], vec![(0x80, 0x4dff), (0x4e01, 0x10ffff)]];
        for round in 0..30 {
            let n = [1, 2, 4, 6, 9, 40][round % 6];
            let mut r: Vec<(u32, u32)> = (0..n)
                .map(|_| {
                    let a = 0x80 + rnd() % 0x2_0000;
                    (a, a + [0, 3, 90, 2000, 30000][rnd() as usize % 5])
                })
                .collect();
            r.sort_unstable();
            let mut m: Vec<(u32, u32)> = Vec::new();
            for (lo, hi) in r {
                match m.last_mut() {
                    Some(l) if lo <= l.1 + 1 => l.1 = l.1.max(hi),
                    _ => m.push((lo, hi)),
                }
            }
            sets.push(m);
        }
        for m in &sets {
            let want = enumerated(&mut |wc| m.iter().any(|&(lo, hi)| wc >= lo && wc <= hi));
            let got = mbset::rows_canon(Some(m)).unwrap();
            assert!(got.same(&want), "{loc}: ranges {m:x?}");
            let mut seqs: crate::vec::V<mbset::Seq> = crate::vec::V::new();
            assert!(mbset::rows_seqs(Some(m), &mut seqs));
            assert!(mbset::Canon::of_seqs(&seqs).same(&want), "{loc}: ranges {m:x?} as sequences");
            checked += 1;
        }
    }
    assert!(checked >= 100, "{checked} sets checked");
}

/// FIXLIST #148: GB18030's automaton built from the rows and the intervals of four-byte code indices (`rows_gb_canon`) accepts
/// the same sequences as the trie of the sequences of `rows_seqs` and `runs_in`, for all characters, for sets of values (few and
/// many ranges, the whole four-byte area but one run, a class's ranges) and for none.
#[test]
fn gb18030_rows_canon_is_the_trie_automaton() {
    use crate::mbset;
    let _g = lock();
    let Some(_l) = LocaleGuard::set("zh_CN.gb18030") else { return };
    let runs = mbset::other_runs();
    assert!(runs.len() > 100, "{} runs", runs.len());
    let trie = |r: &[(u32, u32)]| {
        let mut seqs: crate::vec::V<mbset::Seq> = crate::vec::V::new();
        assert!(mbset::rows_seqs(Some(r), &mut seqs));
        let mut set: mbset::Ranges = crate::vec::V::new();
        set.extend_from_slice(r);
        mbset::runs_in(runs, &set, &mut seqs);
        mbset::Canon::of_seqs(&seqs)
    };
    let mut seed = 0x2468_ace0u32;
    let mut rnd = move || {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        seed >> 8
    };
    let mut sets: Vec<Vec<(u32, u32)>> = vec![vec![(0x80, 0x10ffff)], vec![(0x80, 0xd7ff), (0xe000, 0x10ffff)], vec![(0x80, 0x4dff), (0x4e01, 0x10ffff)], vec![(0x10000, 0x10ffff)]];
    // a class's ranges (alphabetic characters: thousands of ranges over the four-byte area)
    let mut alpha: mbset::Ranges = crate::vec::V::new();
    rusty_libc_wchar::wctype::class_runs(1, &mut |lo, hi| alpha.push((lo, hi)));
    mbset::normalize(&mut alpha);
    sets.push(alpha.iter().copied().collect());
    for round in 0..40 {
        let n = [1, 2, 4, 9, 30, 300][round % 6];
        let mut r: Vec<(u32, u32)> = (0..n)
            .map(|_| {
                let a = 0x80 + rnd() % 0x11_0000;
                (a, a + [0, 3, 90, 2000, 30000, 300_000][rnd() as usize % 6])
            })
            .collect();
        r.sort_unstable();
        let mut m: Vec<(u32, u32)> = Vec::new();
        for (lo, hi) in r {
            match m.last_mut() {
                Some(l) if lo <= l.1 + 1 => l.1 = l.1.max(hi),
                _ => m.push((lo, hi.min(0x10ffff))),
            }
        }
        sets.push(m);
    }
    for m in &sets {
        let want = trie(m);
        let got = mbset::rows_gb_canon(Some(m)).unwrap();
        assert!(got.equivalent(&want), "ranges {:x?}", &m[..m.len().min(8)]);
        // (and the checker is not blind: a set that is not this one differs)
        if m.len() == 1 && m[0] != (0x80, 0x10ffff) {
            assert!(!got.equivalent(&trie(&[(0x80, 0x10ffff)])));
        }
    }
    // all characters: the same as the ranges that cover everything
    let all = mbset::rows_gb_canon(None).unwrap();
    assert!(all.equivalent(&trie(&[(0, u32::MAX)])));
    assert!(mbset::rows_gb_canon(Some(&[])).unwrap().equivalent(&mbset::Canon::none()));
}

/// FIXLIST #65, class (a): a back-reference right after an anchor (`$` ...) is checked against the real context at the
/// position, like glibc's transit_state_bkref does; before, `(b$)\1` matched "bb".
/// The expected answers are what glibc 2.43 prints (checked against the host's regexec here as well).
#[test]
fn backref_after_anchor_follows_glibc() {
    let _g = lock();
    let ext = REG_EXTENDED;
    let cases: &[(&[u8], i32, &[u8], i32, usize, Option<&[(i32, i32)]>)] = &[
        (b"(b$)\\1", ext, b"bb", 0, 10, None),
        (b"(b$)\\1", ext | REG_NEWLINE, b"bb", 0, 10, None),
        (b"\\(b$\\)\\1", 0, b"bb", 0, 10, None),
        (b"(0?)$\\1", ext | REG_ICASE, b"xc00--ba aaxx", 0, 11, Some(&[(13, 13), (13, 13)])),
        (b"[A-Za-z]*[^]a](( )?$|[^]a]1|c1)\\2", ext | REG_NOSUB, b"aaax   c1", 0, 0, None),
        (b"[A-Za-z]*[^]a](( )?$|[^]a]1|c1)\\2", ext, b"aaax   c1", 0, 10, None),
    ];
    for &(p, cf, t, ef, nm, want) in cases {
        let c = case(p, cf, t, ef, nm);
        if let Some(d) = compare(&c) {
            panic!("differs from glibc:\n{d}");
        }
        let o = run(false, &c);
        match want {
            None => assert_eq!(o.exec, Some(REG_NOMATCH), "pattern {:?} text {:?}", show(p), show(t)),
            Some(w) => {
                assert_eq!(o.exec, Some(0), "pattern {:?} text {:?}", show(p), show(t));
                assert_eq!(&o.pm[..w.len()], w);
            }
        }
    }
}
