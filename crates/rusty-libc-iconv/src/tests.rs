//! Differential tests against the host's glibc iconv (the oracle): same input, same buffer sizes,
//! same return value, errno, consumed and produced counts and output bytes, call by call.
use crate::Converter;
use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::Mutex;

unsafe extern "C" {
    fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
    fn iconv(cd: *mut c_void, ib: *mut *mut c_char, il: *mut usize, ob: *mut *mut c_char, ol: *mut usize) -> usize;
    fn iconv_close(cd: *mut c_void) -> c_int;
    fn __errno_location() -> *mut c_int;
}

/// Set the host's errno to 0.
fn clear_errno() {
    // SAFETY: __errno_location has no preconditions.
    let p = unsafe { __errno_location() };
    // SAFETY: it returns the calling thread's errno, valid and aligned for the thread's life.
    unsafe { *p = 0 };
}

/// The host's errno.
fn host_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// One call of iconv and what it did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step {
    pub ret: i64,
    pub errno: i32,
    pub consumed: usize,
    pub produced: usize,
    pub out: Vec<u8>,
}

pub trait Conv {
    /// `input` is the data of this call, `outcap` the output room. `input == None`: flush
    /// (with output room `outcap`) when `outcap` is Some-like (non-zero cap flag `flush_out`).
    fn call(&mut self, input: &[u8], outcap: usize) -> Step;
    fn flush(&mut self, outcap: usize) -> Step;
    fn reset(&mut self);
}

pub struct Host(*mut c_void);

impl Host {
    pub fn open(to: &str, from: &str) -> Option<Host> {
        let (t, f) = (CString::new(to).ok()?, CString::new(from).ok()?);
        // SAFETY: both names are NUL-terminated CStrings that outlive the call.
        let cd = unsafe { iconv_open(t.as_ptr(), f.as_ptr()) };
        if cd as usize == usize::MAX { None } else { Some(Host(cd)) }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // SAFETY: a descriptor from the host's iconv_open, closed once.
        unsafe { iconv_close(self.0) };
    }
}

impl Conv for Host {
    fn call(&mut self, input: &[u8], outcap: usize) -> Step {
        let mut inb = input.to_vec();
        inb.push(0);
        let mut out = vec![0u8; outcap + 1];
        let (mut ip, mut il) = (inb.as_mut_ptr() as *mut c_char, input.len());
        let (mut op, mut ol) = (out.as_mut_ptr() as *mut c_char, outcap);
        clear_errno();
        // SAFETY: an open descriptor; the pointers and counts describe `inb` and `out`, which outlive the call.
        let r = unsafe { iconv(self.0, &mut ip, &mut il, &mut op, &mut ol) };
        let e = host_errno();
        out.truncate(outcap - ol);
        Step { ret: r as i64, errno: if r == usize::MAX { e } else { 0 }, consumed: input.len() - il, produced: outcap - ol, out }
    }
    fn flush(&mut self, outcap: usize) -> Step {
        let mut out = vec![0u8; outcap + 1];
        let (mut op, mut ol) = (out.as_mut_ptr() as *mut c_char, outcap);
        clear_errno();
        // SAFETY: an open descriptor; the output pointer and count describe `out`, which outlives the call.
        let r = unsafe { iconv(self.0, std::ptr::null_mut(), std::ptr::null_mut(), &mut op, &mut ol) };
        let e = host_errno();
        out.truncate(outcap - ol);
        Step { ret: r as i64, errno: if r == usize::MAX { e } else { 0 }, consumed: 0, produced: outcap - ol, out }
    }
    fn reset(&mut self) {
        // SAFETY: an open descriptor; the reset form reads no buffer.
        unsafe { iconv(self.0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    }
}

impl Conv for Converter {
    fn call(&mut self, input: &[u8], outcap: usize) -> Step {
        let mut out = vec![0u8; outcap];
        let (mut ip, mut op) = (0, 0);
        let r = self.convert_raw(input, &mut ip, &mut out, &mut op);
        out.truncate(op);
        match r {
            Ok(n) => Step { ret: n as i64, errno: 0, consumed: ip, produced: op, out },
            Err(e) => Step { ret: -1, errno: e.errno(), consumed: ip, produced: op, out },
        }
    }
    fn flush(&mut self, outcap: usize) -> Step {
        let mut out = vec![0u8; outcap];
        let mut op = 0;
        let r = self.flush_raw(Some((&mut out, &mut op)));
        out.truncate(op);
        match r {
            Ok(n) => Step { ret: n as i64, errno: 0, consumed: 0, produced: op, out },
            Err(e) => Step { ret: -1, errno: e.errno(), consumed: 0, produced: op, out },
        }
    }
    fn reset(&mut self) {
        let _ = self.flush_raw(None);
    }
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
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Drive both converters through the same sequence of calls (input split into `in_chunks`, output
/// room `out_chunks`, cycling; after the input a flush) and report the first difference.
pub fn compare_run(to: &str, from: &str, input: &[u8], in_chunks: &[usize], out_chunks: &[usize], do_flush: bool) -> Result<(), String> {
    compared(1);
    let Some(mut h) = Host::open(to, from) else {
        return if Converter::new(to, from).is_err() { Ok(()) } else { Err(format!("{to} <- {from}: host cannot open, we can")) };
    };
    let mut o = Converter::new(to, from).map_err(|e| format!("{to} <- {from}: we cannot open ({e:?})"))?;
    let mut pos = 0;
    let mut k = 0;
    let mut stuck = 0;
    let mut trace = String::new();
    while pos < input.len() && k < 400 {
        let ic = in_chunks[k % in_chunks.len()].max(1);
        let oc = out_chunks[k % out_chunks.len()];
        k += 1;
        let end = (pos + ic).min(input.len());
        let a = h.call(&input[pos..end], oc);
        let b = o.call(&input[pos..end], oc);
        trace += &format!("  call {k}: {pos}..{end} outcap {oc} -> {a:?}\n");
        if a != b {
            return Err(format!(
                "{to} <- {from} input {} call {k} (chunk {pos}..{end}, outcap {oc})\n{trace}  glibc: {a:?}\n  ours:  {b:?}",
                hex(input)
            ));
        }
        if a.consumed == 0 && a.produced == 0 {
            stuck += 1;
            if stuck > 3 {
                break;
            }
        } else {
            stuck = 0;
        }
        pos += a.consumed;
        if a.ret == -1 && a.errno == 84 && a.consumed < end - pos + a.consumed && a.consumed == 0 {
            break;
        }
    }
    if do_flush {
        for oc in [64usize, 0, 1, 2] {
            let a = h.flush(oc);
            let b = o.flush(oc);
            if a != b {
                return Err(format!("{to} <- {from} input {} flush (outcap {oc})\n  glibc: {a:?}\n  ours:  {b:?}", hex(input)));
            }
            if a.ret == 0 && oc == 64 {
                break;
            }
        }
    }
    Ok(())
}

static LOCK: Mutex<()> = Mutex::new(());
thread_local! {
    /// How many conversions this test compared with glibc (printed when the test ends).
    static COMPARED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn compared(n: u64) {
    COMPARED.with(|c| c.set(c.get() + n));
}

/// Prints the number of comparisons of a test when it ends.
struct Report(&'static str);

impl Drop for Report {
    fn drop(&mut self) {
        println!("{}: {} conversions compared with glibc", self.0, COMPARED.with(|c| c.get()));
    }
}

#[test]
fn utf8_basics() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("utf8_basics");
    let cases: &[&[u8]] = &[b"abc", "h\u{e9}llo \u{20ac} \u{1f600}".as_bytes(), b"\xe2\x82", b"\xff", b"a\x80b", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xfc\x84\x80\x80\x80\x80"];
    for c in cases {
        for to in ["UTF-8", "UTF-16", "UTF-16LE", "UTF-16BE", "UTF-32", "UCS-2", "UCS-4", "UCS-4LE", "ASCII", "ISO-8859-1", "ASCII//TRANSLIT", "ASCII//IGNORE", "UNICODE", "UCS-2BE"] {
            for oc in [0usize, 1, 2, 3, 4, 5, 8, 100] {
                compare_run(to, "UTF-8", c, &[100], &[oc, 100], true).unwrap();
            }
        }
    }
}

/// Every implemented charset, as the name `iconv_open` takes.
fn all_charsets() -> Vec<&'static str> {
    crate::names::implemented().collect()
}

fn pair_check(to: &str, from: &str, input: &[u8], outcap: usize, h: &mut Host, o: &mut Converter) -> Result<(), String> {
    pair_check_f(to, from, input, outcap, h, o, true)
}

fn pair_check_f(to: &str, from: &str, input: &[u8], outcap: usize, h: &mut Host, o: &mut Converter, flush: bool) -> Result<(), String> {
    compared(1);
    h.reset();
    o.reset();
    let a = h.call(input, outcap);
    let b = o.call(input, outcap);
    if a != b {
        return Err(format!("{to} <- {from} input {} outcap {outcap}\n  glibc: {a:?}\n  ours:  {b:?}", hex(input)));
    }
    if !flush {
        return Ok(());
    }
    // whatever the conversion holds back or has shifted is written by the flush
    let (fa, fb) = (h.flush(16), o.flush(16));
    if fa != fb {
        return Err(format!("{to} <- {from} input {} outcap {outcap}: flush\n  glibc: {fa:?}\n  ours:  {fb:?}", hex(input)));
    }
    Ok(())
}

/// Every byte (and byte pairs) of every charset decoded to UTF-8.
#[test]
fn exhaustive_decode() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("exhaustive_decode");
    let mut bad = Vec::new();
    for cs in all_charsets() {
        let (Some(mut h), Ok(mut o)) = (Host::open("UTF-8", cs), Converter::new("UTF-8", cs)) else {
            bad.push(format!("{cs}: open mismatch"));
            continue;
        };
        for b in 0..=255u8 {
            if let Err(e) = pair_check("UTF-8", cs, &[b], 16, &mut h, &mut o) {
                bad.push(e);
                break;
            }
            for c in [0x00u8, 0x41, 0x80, 0xa1, 0xbf, 0xfe, 0xff] {
                if let Err(e) = pair_check("UTF-8", cs, &[b, c], 16, &mut h, &mut o) {
                    bad.push(e);
                    break;
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(5)].join("\n"));
}

/// Every character (every one below U+30000, a sample above) of every charset encoded from UCS-4LE,
/// with room for the output, with room for one byte less.
#[test]
fn exhaustive_encode() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("exhaustive_encode");
    let mut bad = Vec::new();
    for cs in all_charsets() {
        let (Some(mut h), Ok(mut o)) = (Host::open(cs, "UCS-4LE"), Converter::new(cs, "UCS-4LE")) else {
            bad.push(format!("{cs}: open mismatch"));
            continue;
        };
        let mut cp = 0u32;
        while cp < 0x8000_0010 {
            let input = cp.to_le_bytes();
            for oc in [16usize, 1] {
                // the flush matters for characters that are held back or shift: look at it for the
                // first ones and every eleventh
                if let Err(e) = pair_check_f(cs, "UCS-4LE", &input, oc, &mut h, &mut o, cp < 0x4000 || cp.is_multiple_of(11)) {
                    bad.push(e);
                    cp = u32::MAX - 20;
                    break;
                }
            }
            cp = if cp < 0x30000 { cp + 1 } else if cp < 0x120000 { cp + 37 } else { cp + 0x10001 * 13 + 7 };
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(5)].join("\n"));
}

/// A character, biased towards the interesting ones.
fn rand_cp(r: &mut Rng) -> u32 {
    match r.below(12) {
        0..=2 => r.below(0x80) as u32,
        3 | 4 => 0x80 + r.below(0x180) as u32,
        5 => 0x2000 + r.below(0x700) as u32,
        6 => 0x3000 + r.below(0x100) as u32,
        7 => [0xfeff, 0xfffe, 0xffff, 0xfffd, 0xd800, 0xdfff, 0x10ffff, 0x110000, 0xe0001, 0xe007f, 0x7fffffff, 0x80000000, 0x20ac, 0x2019, 0x1f600][r.below(15)],
        8 => r.below(0x10000) as u32,
        9 => 0x10000 + r.below(0x100000) as u32,
        10 => 0xa0 + r.below(0x60) as u32,
        _ => r.below(0x3000) as u32,
    }
}

fn put_utf8(v: &mut Vec<u8>, c: u32) {
    // glibc style (up to 6 bytes, surrogates written too: the test wants invalid input as well)
    if c < 0x80 {
        v.push(c as u8);
    } else if c < 0x800 {
        v.extend([0xc0 | (c >> 6) as u8, 0x80 | (c & 63) as u8]);
    } else if c < 0x10000 {
        v.extend([0xe0 | (c >> 12) as u8, 0x80 | ((c >> 6) & 63) as u8, 0x80 | (c & 63) as u8]);
    } else if c < 0x200000 {
        v.extend([0xf0 | (c >> 18) as u8, 0x80 | ((c >> 12) & 63) as u8, 0x80 | ((c >> 6) & 63) as u8, 0x80 | (c & 63) as u8]);
    } else if c < 0x4000000 {
        v.extend([0xf8 | (c >> 24) as u8, 0x80 | ((c >> 18) & 63) as u8, 0x80 | ((c >> 12) & 63) as u8, 0x80 | ((c >> 6) & 63) as u8, 0x80 | (c & 63) as u8]);
    } else {
        v.extend([0xfc | (c >> 30) as u8, 0x80 | ((c >> 24) & 63) as u8, 0x80 | ((c >> 18) & 63) as u8, 0x80 | ((c >> 12) & 63) as u8, 0x80 | ((c >> 6) & 63) as u8, 0x80 | (c & 63) as u8]);
    }
}

fn rand_utf8(r: &mut Rng) -> Vec<u8> {
    let n = r.below(24);
    let mut v = Vec::new();
    for _ in 0..n {
        let c = rand_cp(r);
        if c >= 0x8000_0000 {
            v.push(0xfe);
        } else {
            put_utf8(&mut v, c);
        }
    }
    if r.below(6) == 0 && !v.is_empty() {
        let i = r.below(v.len());
        v[i] = r.next() as u8;
    }
    if r.below(8) == 0 && !v.is_empty() {
        let k = r.below(v.len());
        v.truncate(k);
    }
    v
}

fn rand_raw(r: &mut Rng) -> Vec<u8> {
    let n = r.below(24);
    let mut v = Vec::new();
    if r.below(5) == 0 {
        v.extend([[0xfe, 0xff], [0xff, 0xfe]][r.below(2)]);
    }
    for _ in 0..n {
        match r.below(4) {
            0 => v.push(r.next() as u8),
            1 => v.push(0x20 + r.below(0x5f) as u8),
            2 => v.push(0x80 + r.below(0x80) as u8),
            _ => v.push(r.below(4) as u8 * 0x40 + r.below(8) as u8),
        }
    }
    v
}

fn rand_chunks(r: &mut Rng, zero_ok: bool) -> Vec<usize> {
    (0..4).map(|_| if r.below(3) == 0 { r.below(4) + usize::from(!zero_ok) } else { 1 + r.below(40) }).collect()
}

fn fuzz_cs(cs: &str, iters: usize, seed: u64) -> Vec<String> {
    let mut r = Rng(seed ^ 0x9e37_79b9_7f4a_7c15);
    let mut bad = Vec::new();
    let suffixes = ["", "//TRANSLIT", "//IGNORE", "//TRANSLIT//IGNORE"];
    for it in 0..iters {
        let suf = suffixes[it % 4];
        let to = format!("{cs}{suf}");
        // UTF-8 text into the charset
        let inp = rand_utf8(&mut r);
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        if let Err(e) = compare_run(&to, "UTF-8", &inp, &ic, &oc, true) {
            bad.push(e);
        }
        // raw bytes from the charset
        let inp = rand_raw(&mut r);
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        let other = ["UTF-8", "UTF-16", "UCS-4LE", "ASCII", "UTF-32BE", "ISO-8859-1"][r.below(6)];
        let tgt = format!("{other}{suf}");
        if let Err(e) = compare_run(&tgt, cs, &inp, &ic, &oc, true) {
            bad.push(e);
        }
        // charset to charset through random bytes
        let other2 = ["ISO-8859-2", "CP1252", "UTF-16LE", "UCS-2", "KOI8-R", "IBM437"][r.below(6)];
        let inp = rand_raw(&mut r);
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        if let Err(e) = compare_run(&format!("{other2}{suf}"), cs, &inp, &ic, &oc, false) {
            bad.push(e);
        }
        if bad.len() > 3 {
            break;
        }
    }
    bad
}

#[test]
fn fuzz_all_charsets() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("fuzz_all_charsets");
    let mut bad = Vec::new();
    for (i, cs) in all_charsets().into_iter().enumerate() {
        bad.extend(fuzz_cs(cs, std::env::var("ICONV_FUZZ").ok().and_then(|v| v.parse().ok()).unwrap_or(48), i as u64 + 1));
        if bad.len() > 6 {
            break;
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(4)].join("\n"));
}

#[test]
fn utf7_alphabet_fuzz() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("utf7_alphabet_fuzz");
    let mut r = Rng(77);
    let alpha = b"+-+-AAAAaZ09/,&. ~\\\n+AGE-+2D3eAA-+ADs-+/v8-";
    let mut bad = Vec::new();
    for it in 0..std::env::var("ICONV_FUZZ7").ok().and_then(|v| v.parse().ok()).unwrap_or(30000) {
        let n = r.below(20);
        let inp: Vec<u8> = (0..n).map(|_| if r.below(10) == 0 { r.next() as u8 } else { alpha[r.below(alpha.len())] }).collect();
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        let imap = if it % 2 == 0 { "UTF-7" } else { "UTF-7-IMAP" };
        let to = ["UTF-8", "UTF-16LE", "UCS-4LE", "ASCII//IGNORE", "UTF-8//TRANSLIT"][r.below(5)];
        if let Err(e) = compare_run(to, imap, &inp, &ic, &oc, true) {
            bad.push(e);
            break;
        }
        // and from text into UTF-7
        let text = rand_utf8(&mut r);
        if let Err(e) = compare_run(imap, "UTF-8", &text, &ic, &oc, true) {
            bad.push(e);
            break;
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The names `iconv -l` lists on the host.
fn host_names() -> Vec<String> {
    let out = std::process::Command::new("iconv").arg("-l").output().expect("iconv -l");
    String::from_utf8_lossy(&out.stdout).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
}

/// Names that open on the host but not here: charsets not implemented (the CJK and stateful ones).
#[test]
fn names_against_host() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("names_against_host");
    let mut missing = Vec::new();
    let mut wrong = Vec::new();
    for n in host_names() {
        for form in [n.clone(), n.to_lowercase(), format!("{}//TRANSLIT", n.trim_end_matches('/')), format!("{}//IGNORE", n.trim_end_matches('/')), format!("{}/TRANSLIT/IGNORE", n.trim_end_matches('/')), format!(" {},translit,", n.trim_end_matches('/'))] {
            let h = Host::open("UTF-8", &form).is_some();
            let ht = Host::open(&form, "UTF-8").is_some();
            let o = Converter::new("UTF-8", &form).is_ok();
            let ot = Converter::new(&form, "UTF-8").is_ok();
            if (o && !h) || (ot && !ht) {
                wrong.push(form.clone());
            } else if (h && !o) || (ht && !ot) {
                missing.push(n.clone());
            }
        }
    }
    missing.sort();
    missing.dedup();
    println!("{} names the host opens that we do not", missing.len());
    assert!(wrong.is_empty(), "we open names the host rejects: {wrong:?}");
    assert!(missing.is_empty(), "names `iconv -l` lists that we cannot open: {missing:?}");
    // and the lists are the same, name for name (case and trailing slashes as printed)
    let mut ours: Vec<String> = crate::all_names().map(|n| n.to_string()).collect();
    let mut theirs = host_names();
    ours.sort();
    theirs.sort();
    let only_ours: Vec<&String> = ours.iter().filter(|n| !theirs.contains(n)).collect();
    let only_theirs: Vec<&String> = theirs.iter().filter(|n| !ours.contains(n)).collect();
    assert!(only_ours.is_empty() && only_theirs.is_empty(), "the alias list differs from `iconv -l`: only ours {only_ours:?}, only glibc's {only_theirs:?}");
}

#[test]
fn name_forms() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("name_forms");
    let names = [
        "", "//", "char", "CHAR", "INTERNAL", "WCHAR_T", "wchar_t", "utf8", "UTF8", "utf-8", "Utf-8//", "UTF-8//TRANSLIT", "UTF-8//translit", "UTF-8/TRANSLIT", "UTF-8//TRANSLIT/IGNORE",
        "UTF-8//IGNORE,TRANSLIT", "UTF-8//IGNORE,", "UTF-8//TRANSLIT//", "UTF-8//TRANSLIT/", "UTF-8,TRANSLIT", "UTF-8//FOO", "UTF-8//FOO//TRANSLIT", "UTF-8 ", " UTF-8", "UTF 8", "UTF-8///", "UTF-8////IGNORE",
        "ISO_8859-1", "iso_8859-1", "latin1", "latin-1", "LATIN1//TRANSLIT", "ISO-8859-1:1987", "ISO-8859-1", "ISO8859-1", "8859_1", "ASCII", "US-ASCII", "ANSI_X3.4-1968", "ansi_x3.4-1968//IGNORE", "646", "ISO646-US",
        "UCS-2", "UCS2", "UCS-2LE", "UCS-2BE", "UNICODELITTLE", "UNICODEBIG", "UNICODE", "UCS-4", "UCS4", "UCS-4LE", "UCS-4BE", "ISO-10646", "ISO-10646/UCS4/", "ISO-10646/UTF8/", "ISO-10646/UTF-8/", "10646-1:1993", "UTF-16", "UTF16", "UTF-16LE", "UTF-16BE", "UTF-32", "UTF32LE", "UTF-32BE", "UTF-7", "UTF7", "UTF-7-IMAP",
        "CP1252", "cp1252", "WINDOWS-1252", "MS-ANSI", "CP437", "IBM437", "437", "CP850", "CP866", "KOI8-R", "KOI8-U", "MACINTOSH", "MAC", "NOSUCH", "UTF-8x", "ISO-8859-16", "ISO-8859-12", "ISO-8859-0", "ISO8859-15", "LATIN9", "L1", "CSISOLATIN1", "ÄÖ", "UTF-8\u{1}",
    ];
    for a in names {
        for b in ["UTF-8", "", "ASCII//TRANSLIT", "x"] {
            for (to, from) in [(a, b), (b, a)] {
                let h = Host::open(to, from).is_some();
                let o = Converter::new(to, from).is_ok();
                if h != o {
                    // charsets we do not implement are reported by names_against_host; here only the
                    // name rules are under test
                    let known_missing = ["INTERNAL"].contains(&a);
                    assert!(known_missing, "open({to:?}, {from:?}): host {h}, ours {o}");
                }
            }
        }
    }
}

/// Inputs longer than glibc's 8160-character buffer: the places where an ignored error is
/// reported, and where the output filling up cuts a round, depend on the buffer boundaries.
#[test]
fn large_inputs() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("large_inputs");
    let mut r = Rng(4242);
    let mut bad = Vec::new();
    for it in 0..60 {
        let n = 8000 + r.below(30000);
        let mut text = Vec::new();
        for _ in 0..n {
            if r.below(3000) == 0 {
                text.push(0xe9); // a lone Latin-1 byte: invalid UTF-8
            } else if r.below(5) == 0 {
                put_utf8(&mut text, 0x80 + r.below(0x2000) as u32);
            } else {
                text.push(0x20 + r.below(0x5f) as u8);
            }
        }
        for (to, from) in [("ASCII//IGNORE", "UTF-8"), ("ISO-8859-1//IGNORE", "UTF-8"), ("ISO-8859-1//TRANSLIT//IGNORE", "UTF-8"), ("UTF-16LE//IGNORE", "UTF-8"), ("UTF-8//IGNORE", "UTF-8"), ("CP1252//TRANSLIT", "UTF-8"), ("UTF-7//IGNORE", "UTF-8"), ("ASCII", "UTF-8//IGNORE")] {
            let ic = [if it % 3 == 0 { 100000 } else { 1 + r.below(20000) }];
            let oc = [1 + r.below(70000), 20000 + r.below(90000), 8160, 8161, 100000];
            if let Err(e) = compare_run(to, from, &text, &ic, &oc, true) {
                bad.push(e.chars().take(600).collect::<String>());
            }
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(3)].join("\n"));
}

/// Longer texts with runs of ASCII and of other characters (the fast paths work on runs), cut at
/// random buffer sizes.
#[test]
fn long_runs() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("long_runs");
    let mut r = Rng(99);
    let mut bad = Vec::new();
    let sets = ["UTF-8", "UTF-16", "UTF-16BE", "UTF-16LE", "UCS-2", "UCS-2BE", "UNICODE", "UTF-32", "ASCII", "ISO-8859-1", "CP1252", "KOI8-R", "IBM437", "ISO-8859-15"];
    for it in 0..4000 {
        let mut text = Vec::new();
        for _ in 0..1 + r.below(8) {
            let run = r.below(60);
            let kind = r.below(5);
            for _ in 0..run {
                let c = match kind {
                    0 | 1 => 0x20 + r.below(0x5f) as u32,
                    2 => 0x80 + r.below(0x100) as u32,
                    3 => 0x400 + r.below(0x100) as u32,
                    _ => rand_cp(&mut r),
                };
                if c < 0x8000_0000 {
                    put_utf8(&mut text, c);
                }
            }
        }
        let cs = sets[it % sets.len()];
        let suf = ["", "//TRANSLIT", "//IGNORE"][r.below(3)];
        let (ic, oc) = (vec![1 + r.below(400), 1 + r.below(100)], vec![r.below(200), 1 + r.below(300)]);
        if let Err(e) = compare_run(&format!("{cs}{suf}"), "UTF-8", &text, &ic, &oc, true) {
            bad.push(e.chars().take(900).collect::<String>());
        }
        // and back: whatever the host makes of it, both decode the same
        let mut host = Host::open(&format!("{cs}{suf}"), "UTF-8").unwrap();
        let enc = host.call(&text, 4 * text.len() + 64).out;
        if let Err(e) = compare_run("UTF-8//IGNORE", cs, &enc, &ic, &oc, true) {
            bad.push(e.chars().take(900).collect::<String>());
        }
        if let Err(e) = compare_run("UTF-16LE", cs, &enc, &ic, &oc, false) {
            bad.push(e.chars().take(900).collect::<String>());
        }
        if bad.len() > 3 {
            break;
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(3)].join("\n"));
}

/// The multibyte charsets: every two-byte sequence alone, followed by ASCII, and with //IGNORE
/// (which shows how many bytes an error skips), and every three-byte sequence with a 0x8e/0x8f lead.
#[test]
fn exhaustive_decode_multibyte() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("exhaustive_decode_multibyte");
    let mut bad = Vec::new();
    for cs in crate::cjk_names() {
        let mut variants = Vec::new();
        for target in ["UTF-8", "UTF-16LE//IGNORE"] {
            let (Some(h), Ok(o)) = (Host::open(target, cs), Converter::new(target, cs)) else {
                bad.push(format!("{cs}: open mismatch"));
                continue;
            };
            variants.push((target, h, o));
        }
        'outer: for (target, h, o) in variants.iter_mut() {
            for b1 in 0..=255u8 {
                for b2 in 0..=255u8 {
                    for input in [&[b1, b2][..], &[b1, b2, 0x41, 0x42][..]] {
                        // glibc's UHC steps over U+327E and then skips four bytes when ignoring, past
                        // the end of a short input: not comparable
                        if cs == "UHC" && b1 == 0xa2 && b2 == 0xe8 && target.contains("IGNORE") {
                            continue;
                        }
                        if let Err(e) = pair_check(target, cs, input, 32, h, o) {
                            bad.push(e);
                            break 'outer;
                        }
                    }
                }
            }
            for b1 in [0x8eu8, 0x8f, 0xa1, 0xa2, 0x81, 0x84, 0xfe] {
                for b2 in 0x80..=255u8 {
                    for b3 in (0..=255u8).step_by(1) {
                        if cs == "UHC" && ((b1 == 0xa2 && b2 == 0xe8) || (b2 == 0xa2 && b3 == 0xe8)) && target.contains("IGNORE") {
                            continue;
                        }
                        if let Err(e) = pair_check(target, cs, &[b1, b2, b3], 32, h, o) {
                            bad.push(e);
                            break 'outer;
                        }
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(5)].join("\n"));
}

/// EUC-TW's four-byte codes (8e, plane, row, column) and a three-byte prefix cut short.
#[test]
fn euc_tw_four_byte() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("euc_tw_four_byte");
    let mut h = Host::open("UTF-16LE//IGNORE", "EUC-TW").unwrap();
    let mut o = Converter::new("UTF-16LE//IGNORE", "EUC-TW").unwrap();
    let mut bad = Vec::new();
    'o: for p in 0xa0..=0xb2u8 {
        for r in 0xa0..=0xffu8 {
            for c in 0xa0..=0xffu8 {
                for input in [&[0x8e, p, r, c][..], &[0x8e, p, r, c, 0x41][..], &[0x8e, p, r][..]] {
                    if let Err(e) = pair_check("UTF-16LE//IGNORE", "EUC-TW", input, 32, &mut h, &mut o) {
                        bad.push(e);
                        break 'o;
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// GB18030's four-byte codes: every index range boundary and a sweep, with truncation.
#[test]
fn gb18030_four_byte() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("gb18030_four_byte");
    let mut h = Host::open("UTF-16LE//IGNORE", "GB18030").unwrap();
    let mut o = Converter::new("UTF-16LE//IGNORE", "GB18030").unwrap();
    let mut bad = Vec::new();
    let mut r = Rng(5);
    for it in 0..400000u32 {
        let b = [0x80 + r.below(0x80) as u8, 0x2f + r.below(0xd) as u8, 0x7f_u8.wrapping_add(r.below(0x82) as u8), 0x2f + r.below(0xd) as u8];
        let n = if it % 7 == 0 { 1 + r.below(4) } else { 4 };
        let mut input = b[..n].to_vec();
        if it % 5 == 0 {
            input.push(0x41);
        }
        if let Err(e) = pair_check("UTF-16LE//IGNORE", "GB18030", &input, 32, &mut h, &mut o) {
            bad.push(e);
            break;
        }
    }
    // the linear ranges: boundaries of every run
    for idx in (0u32..0x130000).step_by(97).chain([0x333, 0x334, 0x1d20, 0x1d21, 0x2402, 0x2403, 0x2c40, 0x2c41, 0x4a78, 0x4a79, 0x82bc, 0x82bd, 0x830d, 0x830e, 0x93d4, 0x93d5, 0x99e1, 0x99e2, 0x99fb, 0x99fc, 0x2e247, 0x2e248, 0x12e247, 0x12e248]) {
        let mut v = idx;
        let d4 = (v % 10) as u8 + 0x30;
        v /= 10;
        let d3 = (v % 126) as u8 + 0x81;
        v /= 126;
        let d2 = (v % 10) as u8 + 0x30;
        v /= 10;
        if v >= 126 {
            continue;
        }
        let input = [v as u8 + 0x81, d2, d3, d4];
        if let Err(e) = pair_check("UTF-16LE//IGNORE", "GB18030", &input, 32, &mut h, &mut o) {
            bad.push(e);
            break;
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Stateful 7-bit charsets: texts made of escape sequences and 7-bit code bytes going in, and texts
/// from every script (with language tags) going out, in random chunks.
fn iso2022_fuzz(names: &[&str], iters: usize, seed: u64) {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("iso2022_fuzz");
    let mut r = Rng(seed);
    let escs: &[&[u8]] = &[
        b"\x1b$B", b"\x1b$@", b"\x1b(B", b"\x1b(J", b"\x1b(I", b"\x1b$A", b"\x1b$(C", b"\x1b$(D", b"\x1b.A", b"\x1b.F", b"\x1bNa", b"\x1bN!", b"\x1b", b"\x1b$", b"\x1b$(", b"\x1b(", b"\x0e", b"\x0f", b"\x1b$)C", b"\x1b$)A", b"\x1b$)G", b"\x1b$)E", b"\x1b$*H", b"\x1b$+I", b"\x1bN", b"\x1bO", b"\x1b$(O", b"\x1b$(P", b"\x1b$(Q", b"\x1b$(0", b"\x1b$(1", b"\x1b$(2", b"\x1b$(3", b"\x24\x77", b"\x25\x77", b"\x2b\x44", b"\x2b\x65", b"\x2b\x66", b"\x7e\x7a", b"\x24\x2b", b"\x25\x2b",
    ];
    let pool = |r: &mut Rng| -> u32 {
        match r.below(14) {
            0 => 0x20 + r.below(0x5f) as u32,
            1 => 0xa0 + r.below(0x60) as u32,
            2 => 0x391 + r.below(0x40) as u32,
            3 => 0x410 + r.below(0x40) as u32,
            4 => 0x3041 + r.below(0xbf) as u32,
            5 | 6 => 0x4e00 + r.below(0x5200) as u32,
            7 => 0xac00 + r.below(0x2ba4) as u32,
            8 => 0xff61 + r.below(0x3f) as u32,
            9 => [0xa5, 0x203e, 0x0a, 0x0d, 0, 0x7f, 0x5c, 0x7e, 0x2014, 0x2225, 0xff5e, 0x20ac][r.below(12)],
            10 => [0xe0001, 0xe006a, 0xe0061, 0xe006b, 0xe006f, 0xe007a, 0xe0068, 0xe007f, 0xe0041, 0xe0020][r.below(10)],
            11 => [0x2500 + r.below(0x80) as u32, 0x304b, 0x309a, 0xe6, 0x300, 0x301, 0x254, 0x259, 0x2e5, 0x2e9, 0x20000, 0x25a][r.below(12)],
            12 => 0x3000 + r.below(0x40) as u32,
            _ => rand_cp(r),
        }
    };
    let mut bad = Vec::new();
    for it in 0..iters {
        for name in names {
            let suf = ["", "//TRANSLIT", "//IGNORE", "//TRANSLIT//IGNORE"][it % 4];
            // decoding: escapes and 7-bit bytes (and a few high bytes)
            let mut inp = Vec::new();
            for _ in 0..r.below(14) {
                match r.below(5) {
                    0 | 1 => inp.extend_from_slice(escs[r.below(escs.len())]),
                    2 => inp.push(0x21 + r.below(0x5e) as u8),
                    3 => inp.extend([0x21 + r.below(0x5e) as u8, 0x21 + r.below(0x5e) as u8]),
                    _ => inp.push(if r.below(8) == 0 { r.next() as u8 } else { 0x20 + r.below(0x60) as u8 }),
                }
            }
            let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
            let tgt = ["UTF-8", "UTF-16LE", "UCS-4LE", "ASCII"][r.below(4)];
            if let Err(e) = compare_run(&format!("{tgt}{}", if suf.contains("IGNORE") { "//IGNORE" } else { "" }), name, &inp, &ic, &oc, true) {
                bad.push(e);
            }
            // encoding
            let mut text = Vec::new();
            for _ in 0..r.below(16) {
                let c = pool(&mut r);
                put_utf8(&mut text, c);
            }
            let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
            if let Err(e) = compare_run(&format!("{name}{suf}"), "UTF-8", &text, &ic, &oc, true) {
                bad.push(e);
            }
            if bad.len() > 3 {
                break;
            }
        }
        if bad.len() > 3 {
            break;
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(3)].join("\n"));
}

include!("tests_extra.rs");
include!("tests_names.rs");

#[test]
fn iso2022jp_fuzz() {
    iso2022_fuzz(&["ISO-2022-JP", "ISO-2022-JP-2", "ISO-2022-JP-3", "ISO-2022-KR", "ISO-2022-CN"], std::env::var("ICONV_FUZZ2022").ok().and_then(|v| v.parse().ok()).unwrap_or(20000), 31);
}

/// One descriptor used for several messages: random sequences of conversion calls, flushes (with
/// room for the reset sequence or without), and resets, compared call by call.
#[test]
fn reset_and_flush_sequences() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("reset_and_flush_sequences");
    let mut r = Rng(2024);
    let pairs: &[(&str, &str)] = &[
        ("UTF-16", "UTF-8"), ("UTF-32", "UTF-8"), ("UNICODE", "UTF-8"), ("UTF-8", "UTF-16"), ("UTF-8", "UTF-32"), ("UTF-8", "UNICODE"), ("UTF-16LE", "UTF-16"), ("UTF-7", "UTF-8"), ("UTF-8", "UTF-7"),
        ("UTF-7-IMAP", "UTF-8"), ("ISO-2022-JP", "UTF-8"), ("ISO-2022-JP-2", "UTF-8"), ("ISO-2022-KR", "UTF-8"), ("ISO-2022-CN", "UTF-8"), ("UTF-8", "ISO-2022-JP"), ("UTF-8", "ISO-2022-KR"), ("UTF-8", "ISO-2022-CN"),
        ("EUC-JP", "UTF-8"), ("BIG5-HKSCS", "UTF-8"), ("UTF-8", "BIG5-HKSCS"), ("UTF-16LE", "BIG5-HKSCS"), ("BIG5-HKSCS", "UTF-16LE"), ("ASCII//TRANSLIT", "UTF-8"), ("UTF-16//TRANSLIT", "UTF-8"), ("ISO-8859-1", "UTF-16"), ("UTF-8", "UCS-2"), ("UCS-4", "UTF-16"),
    ];
    let mut bad = Vec::new();
    for &(to, from) in pairs {
        for _ in 0..3000 {
            let mut h = Host::open(to, from).unwrap();
            let mut o = Converter::new(to, from).unwrap();
            let mut trace = String::new();
            for _ in 0..10 {
                let (a, b, what) = match r.below(6) {
                    0..=3 => {
                        let input = if from.starts_with("UTF-8") || from == "UTF-7" || from == "UTF-7-IMAP" { if from.starts_with("UTF-7") { b"A+AGE-~+2D3eAA-x".to_vec() } else { rand_utf8(&mut r) } } else { rand_raw(&mut r) };
                        let oc = r.below(40);
                        (h.call(&input, oc), o.call(&input, oc), format!("call {} room {oc}", hex(&input)))
                    }
                    4 => {
                        let oc = [0, 1, 2, 4, 16][r.below(5)];
                        (h.flush(oc), o.flush(oc), format!("flush room {oc}"))
                    }
                    _ => {
                        h.reset();
                        o.reset();
                        continue;
                    }
                };
                trace += &format!("  {what}: {a:?}\n");
                if a != b {
                    bad.push(format!("{to} <- {from}\n{trace}  ours: {b:?}"));
                    break;
                }
            }
            if !bad.is_empty() {
                break;
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn rust_vec_api() {
    use crate::Converter;
    let out = Converter::convert_all("UTF-16LE", "UTF-8", "h\u{e9}llo \u{1f600}".as_bytes()).unwrap();
    assert_eq!(out, [0x68, 0, 0xe9, 0, 0x6c, 0, 0x6c, 0, 0x6f, 0, 0x20, 0, 0x3d, 0xd8, 0x00, 0xde]);
    let mut c = Converter::new("ISO-2022-JP", "UTF-8").unwrap();
    let mut v = Vec::new();
    c.convert("a\u{3042}".as_bytes(), &mut v).unwrap();
    c.finish(&mut v).unwrap();
    assert_eq!(v, b"a\x1b$B$\"\x1b(B");
    let e = Converter::convert_all("ASCII", "UTF-8", "ab\u{e9}".as_bytes()).unwrap_err();
    assert!(matches!(e, crate::api::OneShotError::Convert(c) if c.kind == crate::Error::Ilseq && c.consumed == 2));
    assert!(Converter::convert_all("NOSUCH", "UTF-8", b"").is_err());
    assert_eq!(crate::canonical_name("latin1"), Some("ISO-8859-1"));
    assert!(crate::all_names().count() > 1000);
}

/// BIG5-HKSCS: the four combining pairs, held-back characters, queued second characters.
#[test]
fn hkscs_combining() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("hkscs_combining");
    let mut r = Rng(8);
    let chars: [u32; 10] = [0xca, 0xea, 0x304, 0x30c, 0x41, 0x4e00, 0xe9, 0x20000, 0x8866, 0x3000];
    let mut bad = Vec::new();
    for _ in 0..20000 {
        let mut text = Vec::new();
        for _ in 0..r.below(8) {
            put_utf8(&mut text, chars[r.below(chars.len())]);
        }
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        if let Err(e) = compare_run("BIG5-HKSCS", "UTF-8", &text, &ic, &oc, true) {
            bad.push(e);
            break;
        }
        let codes: [&[u8]; 8] = [b"\x88\x62", b"\x88\x64", b"\x88\xa3", b"\x88\xa5", b"\x88\x66", b"\x88\xa7", b"A", b"\xfa\x40"];
        let mut raw = Vec::new();
        for _ in 0..r.below(6) {
            raw.extend_from_slice(codes[r.below(codes.len())]);
        }
        for target in ["UTF-8", "UTF-16LE", "UCS-4LE"] {
            if let Err(e) = compare_run(target, "BIG5-HKSCS", &raw, &ic, &oc, true) {
                bad.push(e);
                break;
            }
        }
        if !bad.is_empty() {
            break;
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Charsets that compose, decompose and shift: texts built from base letters, combining marks,
/// precomposed letters and the characters of their repertoire, and byte strings made of their codes.
#[test]
fn composing_and_shifting_fuzz() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("composing_and_shifting_fuzz");
    let mut r = Rng(1234);
    // (charset, characters to draw from, byte strings to draw from)
    type Case<'a> = (&'a str, &'a [u32], &'a [&'a [u8]]);
    let cases: &[Case] = &[
        ("CP1255", &[0x05d0, 0x05d1, 0x05d9, 0x05e9, 0x05f2, 0x05b4, 0x05b7, 0x05b8, 0x05b9, 0x05bc, 0x05bf, 0x05c1, 0x05c2, 0xfb1d, 0xfb2a, 0xfb2c, 0xfb49, 0xfb4b, 0x41, 0x20ac, 0x05b1, 0xe9], &[b"\xe9", b"\xe0", b"\xe9\xcc", b"\xe9\xc1", b"\xe9\xcc\xc1", b"\xe9\xc1\xcc", b"\xcc", b"\xc4", b"A", b"\xd4", b"\xd5\xc9"]),
        ("CP1258", &[0x41, 0x61, 0x45, 0xc2, 0xca, 0xd4, 0x1a0, 0x1af, 0x300, 0x301, 0x303, 0x309, 0x323, 0x1ea0, 0x1eb0, 0x1ec6, 0xe9, 0x20ac, 0x1ef9, 0x302], &[b"A", b"a", b"\xc2", b"\xca", b"\xcc", b"\xec", b"\xde", b"\xf2", b"\xd2", b"\xd0", b"z", b"\xc3"]),
        ("TCVN5712-1", &[0x41, 0x61, 0xc2, 0xca, 0xd4, 0x1a0, 0x1af, 0x300, 0x301, 0x303, 0x309, 0x323, 0x1ea0, 0x1eb0, 0x1ec6, 0xe0, 0x1ef9, 0x2, 0x17], &[b"A", b"a", b"\xb0", b"\xb1", b"\xb2", b"\xb3", b"\xb4", b"\xa1", b"\xa2", b"\x01", b"\x80", b"\xc0"]),
        ("IBM930", &[0x41, 0x3042, 0x4e00, 0xff71, 0x5c, 0x7e, 0x20, 0x4e9c, 0x30a2, 0x0a], &[b"\x0e", b"\x0f", b"\x0e\x44\x81", b"\x0e\x45\x41", b"\xc1", b"\x81", b"\x40", b"\x0e\x42\x42"]),
        ("IBM935", &[0x41, 0x4e00, 0x554a, 0xff71, 0x5c, 0x7e, 0x20], &[b"\x0e", b"\x0f", b"\x0e\x45\x41", b"\xc1", b"\x0e\x40\x40", b"\x0e\x4c\x41"]),
        ("IBM1364", &[0x41, 0xac00, 0x4e00, 0x20, 0x20a9, 0xff71, 0x5c, 0x7e], &[b"\x0e", b"\x0f", b"\x0e\x45\x41", b"\xc1", b"\x0e\x42\x42"]),
        ("IBM1390", &[0x41, 0x3042, 0x304b, 0x309a, 0x4e00, 0xe6, 0x300, 0x2e5, 0x2e9, 0x20000, 0x5c], &[b"\x0e", b"\x0f", b"\x0e\x44\x81", b"\x0e\x45\x41", b"\xc1", b"\x0e\x4a\x4a"]),
        ("IBM1399", &[0x41, 0x3042, 0x304b, 0x309a, 0x4e00, 0xe6, 0x300, 0x2e5, 0x2e9, 0x20000, 0x5c], &[b"\x0e", b"\x0f", b"\x0e\x44\x81", b"\x0e\x45\x41", b"\xc1", b"\x0e\x4a\x4a"]),
        ("IBM1371", &[0x41, 0x4e00, 0x554a, 0xff71, 0x5c], &[b"\x0e", b"\x0f", b"\x0e\x45\x41", b"\xc1"]),
        ("IBM1388", &[0x41, 0x4e00, 0x554a, 0xff71, 0x5c], &[b"\x0e", b"\x0f", b"\x0e\x45\x41", b"\xc1"]),
        ("IBM937", &[0x41, 0x4e00, 0x554a, 0xff71, 0x5c], &[b"\x0e", b"\x0f", b"\x0e\x45\x41", b"\xc1"]),
        ("IBM933", &[0x41, 0xac00, 0x4e00, 0x5c], &[b"\x0e", b"\x0f", b"\x0e\x45\x41", b"\xc1"]),
        ("IBM939", &[0x41, 0x3042, 0x4e00, 0xff71, 0x5c], &[b"\x0e", b"\x0f", b"\x0e\x44\x81", b"\xc1"]),
        ("EUC-JISX0213", &[0x304b, 0x309a, 0xe6, 0x300, 0x301, 0x254, 0x28c, 0x2e5, 0x2e9, 0x3042, 0x20000, 0x4e00, 0xff71, 0x41, 0x30ab, 0x31f7, 0x259, 0x25a], &[b"\xa4\xf7", b"\xa4\xab", b"\xab\xc4", b"\xab\xe5", b"\xab\xe6", b"\xa5\xfe", b"\x8f\xa1\xa1", b"\x8e\xb1", b"\xa1\xa1", b"A"]),
        ("SHIFT_JISX0213", &[0x304b, 0x309a, 0xe6, 0x300, 0x301, 0x254, 0x28c, 0x2e5, 0x2e9, 0x3042, 0x20000, 0x4e00, 0xff71, 0x41, 0x5c, 0xa5, 0x203e, 0x7e], &[b"\x82\xf5", b"\x82\xa9", b"\x86\x63", b"\x86\x85", b"\x86\x86", b"\x83\x9e", b"\xb1", b"\x5c", b"\x7e", b"\x81\x40"]),
    ];
    let mut bad = Vec::new();
    for &(name, pool, codes) in cases {
        for it in 0..6000 {
            let suf = ["", "//TRANSLIT", "//IGNORE", "//TRANSLIT//IGNORE"][it % 4];
            let mut text = Vec::new();
            for _ in 0..r.below(10) {
                put_utf8(&mut text, if r.below(10) == 0 { rand_cp(&mut r) } else { pool[r.below(pool.len())] });
            }
            let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
            if let Err(e) = compare_run(&format!("{name}{suf}"), "UTF-8", &text, &ic, &oc, true) {
                bad.push(e);
            }
            let mut raw = Vec::new();
            for _ in 0..r.below(8) {
                raw.extend_from_slice(codes[r.below(codes.len())]);
            }
            let tgt = ["UTF-8", "UTF-16LE", "UCS-4LE"][r.below(3)];
            let tgt = format!("{tgt}{}", if suf.contains("IGNORE") { "//IGNORE" } else { "" });
            if let Err(e) = compare_run(&tgt, name, &raw, &ic, &oc, true) {
                bad.push(e);
            }
            if bad.len() > 2 {
                break;
            }
        }
        if bad.len() > 2 {
            break;
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(3)].join("\n"));
}

#[test]
fn iso2022jp3_fuzz() {
    iso2022_fuzz(&["ISO-2022-JP-3"], std::env::var("ICONV_FUZZ2022").ok().and_then(|v| v.parse().ok()).unwrap_or(30000), 77);
}

/// glibc converts a few pairs directly (EUC-CN <-> BIG5, GBK <-> EUC-CN, IBM1008 <-> IBM420) instead of
/// through UCS-4, with different handling of invalid input and full buffers; direct.rs does the same.
#[test]
fn direct_pairs() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("direct_pairs");
    let mut r = Rng(555);
    let mut differing = Vec::new();
    for (to, from) in [("EUC-CN", "BIG5"), ("BIG5", "EUC-CN"), ("GBK", "EUC-CN"), ("EUC-CN", "GBK"), ("IBM1008", "IBM420"), ("IBM420", "IBM1008")] {
        let mut bad = 0;
        let mut first = String::new();
        for it in 0..4000 {
            let mut input = rand_raw(&mut r);
            if it % 2 == 0 {
                // valid text of the source charset, made by the host
                let mut h = Host::open(from, "UTF-8").unwrap();
                let text = rand_utf8(&mut r);
                let s = h.call(&text, 200);
                if s.ret >= 0 {
                    input = s.out;
                }
            }
            let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
            if let Err(e) = compare_run(to, from, &input, &ic, &oc, true) {
                bad += 1;
                if first.is_empty() {
                    first = e;
                }
            }
        }
        println!("{to} <- {from}: {bad} of 4000 runs differ from glibc's direct converter{}", if bad > 0 { format!("\nfirst: {first}") } else { String::new() });
        if bad > 0 {
            differing.push(format!("{to} <- {from}"));
        }
    }
    assert!(differing.is_empty(), "pairs that differ from glibc: {differing:?}");
}
