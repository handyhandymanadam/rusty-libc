use crate::api::{self, Compiled};
use crate::consts::*;
use crate::exec::Reg;
use crate::vec::V;
use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU64, Ordering};
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;
use view::{Pattern, Registers};

pub type RegoffT = i32;
pub type RegMatch = Reg;

#[repr(C)]
pub struct RePatternBuffer {
    pub buffer: *mut c_void,
    pub allocated: usize,
    pub used: usize,
    pub syntax: c_ulong,
    pub fastmap: *mut c_char,
    pub translate: *mut u8,
    pub re_nsub: usize,
    pub bits: u32,
    pub _pad: u32,
}
pub type RegexT = RePatternBuffer;

#[repr(C)]
pub struct ReRegisters {
    pub num_regs: u32,
    pub start: *mut RegoffT,
    pub end: *mut RegoffT,
}

const B_CAN_BE_NULL: u32 = 1;
const B_REGS_SHIFT: u32 = 1;
const B_FASTMAP_ACCURATE: u32 = 1 << 3;
const B_NO_SUB: u32 = 1 << 4;
const B_NOT_BOL: u32 = 1 << 5;
const B_NOT_EOL: u32 = 1 << 6;
const B_NEWLINE_ANCHOR: u32 = 1 << 7;

impl RePatternBuffer {
    pub const ZERO: RePatternBuffer =
        RePatternBuffer { buffer: null_mut(), allocated: 0, used: 0, syntax: 0, fastmap: null_mut(), translate: null_mut(), re_nsub: 0, bits: 0, _pad: 0 };

    fn flag(&self, b: u32) -> bool {
        self.bits & b != 0
    }
    fn set_flag(&mut self, b: u32, on: bool) {
        if on {
            self.bits |= b;
        } else {
            self.bits &= !b;
        }
    }
    fn regs_allocated(&self) -> u32 {
        (self.bits >> B_REGS_SHIFT) & 3
    }
    fn set_regs_allocated(&mut self, v: u32) {
        self.bits = (self.bits & !(3 << B_REGS_SHIFT)) | ((v & 3) << B_REGS_SHIFT);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static re_syntax_options: AtomicU64 = AtomicU64::new(0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static re_max_failures: AtomicI32 = AtomicI32::new(2000);

const _: () = assert!(size_of::<AtomicU64>() == size_of::<c_ulong>() && size_of::<AtomicPtr<c_char>>() == size_of::<*mut c_char>());

mod view {
    use super::*;
    use core::ops::Deref;

    #[repr(transparent)]
    pub struct Pattern(RePatternBuffer);

    impl Deref for Pattern {
        type Target = RePatternBuffer;
        #[inline(always)]
        fn deref(&self) -> &RePatternBuffer {
            &self.0
        }
    }

    impl Pattern {
        pub const ZERO: Pattern = Pattern(RePatternBuffer::ZERO);

        #[inline(always)]
        pub unsafe fn from_ptr<'a>(p: *const RegexT) -> &'a Pattern {
            unsafe { &*p.cast::<Pattern>() }
        }

        #[inline(always)]
        pub unsafe fn from_mut_ptr<'a>(p: *mut RegexT) -> &'a mut Pattern {
            unsafe { &mut *p.cast::<Pattern>() }
        }

        pub fn init(raw: &mut RePatternBuffer) -> Option<&mut Pattern> {
            raw.buffer = null_mut();
            raw.allocated = 0;
            raw.used = 0;
            raw.fastmap = unsafe { rusty_libc_malloc::malloc(256) } as *mut c_char;
            if raw.fastmap.is_null() {
                return None;
            }
            raw.translate = null_mut();
            let p: *mut RegexT = raw;
            Some(unsafe { &mut *p.cast::<Pattern>() })
        }

        pub fn set_flag(&mut self, b: u32, on: bool) {
            self.0.set_flag(b, on);
        }

        pub fn compiled(&self) -> Option<&Compiled> {
            let b = self.0.buffer as *const Compiled;
            if b.is_null() || self.0.used == 0 {
                return None;
            }
            if unsafe { (*b).magic } != api::MAGIC {
                return None;
            }
            Some(unsafe { &*b })
        }

        pub fn translate(&self) -> Option<&[u8; 256]> {
            unsafe { self.0.translate.cast::<[u8; 256]>().as_ref() }
        }

        pub fn fastmap(&self) -> Option<&[u8; 256]> {
            unsafe { self.0.fastmap.cast::<[u8; 256]>().as_ref() }
        }

        pub fn compile(&mut self, pat: &[u8], syntax: u64) -> i32 {
            self.0.set_flag(B_FASTMAP_ACCURATE | B_NOT_BOL | B_NOT_EOL | B_CAN_BE_NULL, false);
            self.0.syntax = syntax as c_ulong;
            self.0.used = 0;
            self.0.re_nsub = 0;
            self.0.set_regs_allocated(REGS_UNALLOCATED);
            self.free_compiled();
            match api::compile(pat, syntax, self.translate()) {
                Ok(c) => {
                    let sz = core::mem::size_of::<Compiled>();
                    let mem = unsafe { rusty_libc_malloc::malloc(sz) } as *mut Compiled;
                    if mem.is_null() {
                        return REG_ESPACE;
                    }
                    self.0.re_nsub = c.nfa.nsub as usize;
                    unsafe { mem.write(c) };
                    self.0.buffer = mem.cast();
                    self.0.allocated = sz;
                    self.0.used = sz;
                    REG_NOERROR
                }
                Err(e) => {
                    self.0.buffer = null_mut();
                    self.0.allocated = 0;
                    e
                }
            }
        }

        pub fn free_compiled(&mut self) {
            let b = self.0.buffer as *mut Compiled;
            if !b.is_null()
                && self.0.allocated == core::mem::size_of::<Compiled>()
                && unsafe { (*b).magic } == api::MAGIC
            {
                unsafe { core::ptr::drop_in_place(b) };
                unsafe { rusty_libc_malloc::free(b.cast()) };
            }
            self.0.buffer = null_mut();
            self.0.allocated = 0;
        }

        pub fn compile_fastmap(&mut self) -> c_int {
            let Some(c) = self.compiled() else { return 0 };
            if self.0.fastmap.is_null() {
                return 0;
            }
            let mut fm = [0u8; 256];
            let mut cbn = false;
            c.nfa.fastmap(self.0.syntax & RE_ICASE != 0, &mut fm, &mut cbn);
            if let Some(dst) = unsafe { self.0.fastmap.cast::<[u8; 256]>().as_mut() } {
                *dst = fm;
            }
            if cbn {
                self.0.set_flag(B_CAN_BE_NULL, true);
            }
            self.0.set_flag(B_FASTMAP_ACCURATE, true);
            0
        }

        pub fn alloc_fastmap(&mut self) -> bool {
            self.0.fastmap = unsafe { rusty_libc_malloc::malloc(256) } as *mut c_char;
            !self.0.fastmap.is_null()
        }

        pub unsafe fn free_fastmap(&mut self) {
            if !self.0.fastmap.is_null() {
                unsafe { rusty_libc_malloc::free(self.0.fastmap.cast()) };
            }
            self.0.fastmap = null_mut();
        }

        pub unsafe fn free_translate(&mut self) {
            if !self.0.translate.is_null() {
                unsafe { rusty_libc_malloc::free(self.0.translate.cast()) };
            }
            self.0.translate = null_mut();
        }

        pub fn clear_keep_fastmap(&mut self) {
            let fastmap = self.0.fastmap;
            self.free_compiled();
            self.0 = RePatternBuffer::ZERO;
            self.0.fastmap = fastmap;
        }

        pub fn copy_regs(&mut self, regs: &mut Registers, pmatch: &[Reg]) -> u32 {
            let ra = regs.fill(pmatch, self.0.regs_allocated());
            self.0.set_regs_allocated(ra);
            ra
        }

        pub unsafe fn set_registers(&mut self, regs: &mut Registers, num_regs: u32, starts: *mut RegoffT, ends: *mut RegoffT) {
            if num_regs != 0 {
                self.0.set_regs_allocated(REGS_REALLOCATE);
                regs.0.num_regs = num_regs;
                regs.0.start = starts;
                regs.0.end = ends;
            } else {
                self.0.set_regs_allocated(REGS_UNALLOCATED);
                regs.0.num_regs = 0;
                regs.0.start = null_mut();
                regs.0.end = null_mut();
            }
        }
    }

    #[repr(transparent)]
    pub struct Registers(ReRegisters);

    impl Deref for Registers {
        type Target = ReRegisters;
        #[inline(always)]
        fn deref(&self) -> &ReRegisters {
            &self.0
        }
    }

    impl Registers {
        #[inline(always)]
        pub unsafe fn from_mut_ptr<'a>(p: *mut ReRegisters) -> Option<&'a mut Registers> {
            unsafe { p.cast::<Registers>().as_mut() }
        }

        #[inline(always)]
        pub unsafe fn from_mut_ptr_nonnull<'a>(p: *mut ReRegisters) -> &'a mut Registers {
            unsafe { &mut *p.cast::<Registers>() }
        }

        fn fill(&mut self, pmatch: &[Reg], regs_allocated: u32) -> u32 {
            let r = &mut self.0;
            let nregs = pmatch.len();
            let need = nregs + 1;
            let mut rval = REGS_REALLOCATE;
            if regs_allocated == REGS_UNALLOCATED {
                r.start = unsafe { rusty_libc_malloc::malloc(need * 4) } as *mut RegoffT;
                if r.start.is_null() {
                    return REGS_UNALLOCATED;
                }
                r.end = unsafe { rusty_libc_malloc::malloc(need * 4) } as *mut RegoffT;
                if r.end.is_null() {
                    unsafe { rusty_libc_malloc::free(r.start.cast()) };
                    return REGS_UNALLOCATED;
                }
                r.num_regs = need as u32;
            } else if regs_allocated == REGS_REALLOCATE {
                if need > r.num_regs as usize {
                    let ns = unsafe { rusty_libc_malloc::realloc(r.start.cast(), need * 4) } as *mut RegoffT;
                    if ns.is_null() {
                        return REGS_UNALLOCATED;
                    }
                    let ne = unsafe { rusty_libc_malloc::realloc(r.end.cast(), need * 4) } as *mut RegoffT;
                    if ne.is_null() {
                        unsafe { rusty_libc_malloc::free(ns.cast()) };
                        return REGS_UNALLOCATED;
                    }
                    r.start = ns;
                    r.end = ne;
                    r.num_regs = need as u32;
                }
            } else {
                rval = REGS_FIXED;
            }
            let n = r.num_regs as usize;
            let starts = unsafe { ffi::slice_mut(r.start, n) };
            let ends = unsafe { ffi::slice_mut(r.end, n) };
            for (i, (s, e)) in starts.iter_mut().zip(ends.iter_mut()).enumerate() {
                (*s, *e) = match pmatch.get(i) {
                    Some(m) => (m.so, m.eo),
                    None => (-1, -1),
                };
            }
            rval
        }
    }
}

fn fastmap_in_use(p: &Pattern, start: isize, last_start: isize) -> Option<&[u8; 256]> {
    if p.flag(B_FASTMAP_ACCURATE) && start != last_start && !p.flag(B_CAN_BE_NULL) { p.fastmap() } else { None }
}

fn xlat_for<'a>(p: &'a Pattern, c: &'a Compiled, buf: &'a mut [u8; 256]) -> &'a [u8; 256] {
    match p.translate() {
        None => &c.xlat,
        Some(t) => {
            *buf = api::make_xlat(p.syntax & RE_ICASE != 0, Some(t));
            buf
        }
    }
}

fn regcomp_in(p: &mut Pattern, pat: &[u8], cflags: c_int) -> c_int {
    let mut syntax = if cflags & REG_EXTENDED != 0 { RE_SYNTAX_POSIX_EXTENDED } else { RE_SYNTAX_POSIX_BASIC };
    if cflags & REG_ICASE != 0 {
        syntax |= RE_ICASE;
    }
    if cflags & REG_NEWLINE != 0 {
        syntax &= !RE_DOT_NEWLINE;
        syntax |= RE_HAT_LISTS_NOT_NEWLINE;
        p.set_flag(B_NEWLINE_ANCHOR, true);
    } else {
        p.set_flag(B_NEWLINE_ANCHOR, false);
    }
    p.set_flag(B_NO_SUB, cflags & REG_NOSUB != 0);
    let mut ret = p.compile(pat, syntax);
    if ret == REG_ERPAREN {
        ret = REG_EPAREN;
    }
    if ret == REG_NOERROR {
        p.compile_fastmap();
    } else {
        unsafe { p.free_fastmap() };
    }
    ret
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regcomp(preg: *mut RegexT, pattern: *const c_char, cflags: c_int) -> c_int {
    let raw = unsafe { &mut *preg };
    let Some(p) = Pattern::init(raw) else { return REG_ESPACE };
    let pat = unsafe { ffi::cstr_bytes(pattern) };
    regcomp_in(p, pat, cflags)
}

fn copy_message(msg: &[u8], buf: &mut [u8]) -> usize {
    let msg_size = msg.len() + 1;
    if !buf.is_empty() {
        if msg_size > buf.len() {
            let cpy = buf.len() - 1;
            buf[cpy] = 0;
            buf[..cpy].copy_from_slice(&msg[..cpy]);
        } else {
            buf[..msg.len()].copy_from_slice(msg);
            buf[msg.len()] = 0;
        }
    }
    msg_size
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regerror(errcode: c_int, _preg: *const RegexT, errbuf: *mut c_char, errbuf_size: usize) -> usize {
    if error_message(errcode).is_none() {
        rusty_libc_core::process::abort();
    }
    let msg = rusty_libc_core::i18n::tr(ERROR_MSGS[errcode as usize]);
    let buf = unsafe { ffi::bytes_mut(errbuf.cast::<u8>(), errbuf_size) };
    copy_message(msg.to_bytes(), buf)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regfree(preg: *mut RegexT) {
    let p = unsafe { Pattern::from_mut_ptr(preg) };
    p.free_compiled();
    unsafe { p.free_fastmap() };
    unsafe { p.free_translate() };
}

fn exec(p: &Pattern, text: &[u8], start: isize, pmatch: &mut [Reg], eflags: c_int) -> c_int {
    let Some(c) = p.compiled() else { return REG_NOMATCH };
    let length = text.len();
    let mut xbuf = [0u8; 256];
    let xlat = xlat_for(p, c, &mut xbuf);
    let fm = fastmap_in_use(p, start, length as isize);
    let nm = pmatch.len();
    let err = api::run(c, xlat, p.flag(B_NEWLINE_ANCHOR), text, start, length as isize, length, eflags, nm, pmatch, fm, p.translate());
    (err != REG_NOERROR) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regexec(preg: *const RegexT, string: *const c_char, nmatch: usize, pmatch: *mut RegMatch, eflags: c_int) -> c_int {
    if eflags & !(REG_NOTBOL | REG_NOTEOL | REG_STARTEND) != 0 {
        return REG_BADPAT;
    }
    let (start, text): (isize, &[u8]);
    if eflags & REG_STARTEND != 0 {
        let m = unsafe { pmatch.read() };
        if m.so < 0 || m.eo < 0 {
            return REG_NOMATCH;
        }
        start = m.so as isize;
        text = unsafe { ffi::bytes(string.cast::<u8>(), m.eo as usize) };
    } else {
        start = 0;
        text = unsafe { ffi::cstr_bytes(string) };
    }
    let p = unsafe { Pattern::from_ptr(preg) };
    let pm: &mut [Reg] = if p.flag(B_NO_SUB) || nmatch == 0 {
        &mut []
    } else {
        unsafe { ffi::slice_mut(pmatch, nmatch) }
    };
    exec(p, text, start, pm, eflags)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn re_set_syntax(syntax: c_ulong) -> c_ulong {
    let old = re_syntax_options.load(Ordering::Relaxed);
    re_syntax_options.store(syntax, Ordering::Relaxed);
    old
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_compile_pattern(pattern: *const c_char, length: usize, bufp: *mut RePatternBuffer) -> *const c_char {
    let p = unsafe { Pattern::from_mut_ptr(bufp) };
    let pat = unsafe { ffi::bytes(pattern.cast::<u8>(), length) };
    let syntax = re_syntax_options.load(Ordering::Relaxed);
    p.set_flag(B_NO_SUB, syntax & RE_NO_SUB != 0);
    p.set_flag(B_NEWLINE_ANCHOR, true);
    let ret = p.compile(pat, syntax);
    if ret == REG_NOERROR { null() } else { ERROR_MSGS[ret as usize].as_ptr().cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_compile_fastmap(bufp: *mut RePatternBuffer) -> c_int {
    unsafe { Pattern::from_mut_ptr(bufp) }.compile_fastmap()
}

#[allow(clippy::too_many_arguments)]
fn search(p: &mut Pattern, text: &[u8], start: isize, range: isize, stop: isize, regs: Option<&mut Registers>, ret_len: bool) -> RegoffT {
    let length = text.len() as isize;
    let mut last_start = start.wrapping_add(range);
    if start < 0 || start > length {
        return -1;
    }
    if length < last_start || (0 <= range && last_start < start) {
        last_start = length;
    } else if last_start < 0 || (range < 0 && start <= last_start) {
        last_start = 0;
    }
    let mut eflags = 0;
    if p.flag(B_NOT_BOL) {
        eflags |= REG_NOTBOL;
    }
    if p.flag(B_NOT_EOL) {
        eflags |= REG_NOTEOL;
    }
    if start < last_start && !p.fastmap.is_null() && !p.flag(B_FASTMAP_ACCURATE) {
        p.compile_fastmap();
    }
    let mut regs = if p.flag(B_NO_SUB) { None } else { regs };
    let nregs: usize = match &regs {
        None => 1,
        Some(r) if p.regs_allocated() == REGS_FIXED && r.num_regs as usize <= p.re_nsub => r.num_regs as usize,
        Some(_) => p.re_nsub + 1,
    };
    if nregs < 1 {
        regs = None;
    }
    let nregs = if regs.is_none() { 1 } else { nregs };
    let Some(c) = p.compiled() else { return -1 };
    let mut pmatch: V<Reg> = V::from_elem(Reg { so: -1, eo: -1 }, nregs);
    if pmatch.oom {
        return -2;
    }
    let mut xbuf = [0u8; 256];
    let xlat = xlat_for(p, c, &mut xbuf);
    let stop = if stop < 0 { 0 } else { stop as usize };
    let fm = fastmap_in_use(p, start, last_start);
    let ft = p.translate();
    let result = api::run(c, xlat, p.flag(B_NEWLINE_ANCHOR), text, start, last_start, stop.min(text.len()), eflags, nregs, &mut pmatch, fm, ft);
    let mut rval: RegoffT = 0;
    if result != REG_NOERROR {
        rval = if result == REG_NOMATCH { -1 } else { -2 };
    } else if let Some(r) = regs
        && p.copy_regs(r, &pmatch) == REGS_UNALLOCATED
    {
        rval = -2;
    }
    if rval == 0 {
        rval = if ret_len { pmatch[0].eo - start as i32 } else { pmatch[0].so };
    }
    rval
}

#[allow(clippy::too_many_arguments)]
unsafe fn search_raw(bufp: *mut RePatternBuffer, string: *const c_char, length: isize, start: isize, range: isize, stop: isize, regs: *mut ReRegisters, ret_len: bool) -> RegoffT {
    if length < 0 {
        return -1;
    }
    let p = unsafe { Pattern::from_mut_ptr(bufp) };
    let regs = unsafe { Registers::from_mut_ptr(regs) };
    let text = unsafe { ffi::bytes(string.cast::<u8>(), length as usize) };
    search(p, text, start, range, stop, regs, ret_len)
}

#[allow(clippy::too_many_arguments)]
unsafe fn search_2_raw(
    bufp: *mut RePatternBuffer,
    string1: *const c_char,
    length1: isize,
    string2: *const c_char,
    length2: isize,
    start: isize,
    range: isize,
    regs: *mut ReRegisters,
    stop: isize,
    ret_len: bool,
) -> RegoffT {
    if length1 < 0 || length2 < 0 || stop < 0 {
        return -2;
    }
    if length1.checked_add(length2).is_none_or(|l| l > i32::MAX as isize) {
        return -2;
    }
    let s1 = unsafe { ffi::bytes(string1.cast::<u8>(), length1 as usize) };
    let s2 = unsafe { ffi::bytes(string2.cast::<u8>(), length2 as usize) };
    let p = unsafe { Pattern::from_mut_ptr(bufp) };
    let regs = unsafe { Registers::from_mut_ptr(regs) };
    let mut joined: V<u8> = V::new();
    let text: &[u8] = if s2.is_empty() {
        s1
    } else if s1.is_empty() {
        s2
    } else {
        joined.extend_from_slice(s1);
        joined.extend_from_slice(s2);
        if joined.oom {
            return -2;
        }
        &joined
    };
    search(p, text, start, range, stop, regs, ret_len)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_match(bufp: *mut RePatternBuffer, string: *const c_char, length: RegoffT, start: RegoffT, regs: *mut ReRegisters) -> RegoffT {
    unsafe { search_raw(bufp, string, length as isize, start as isize, 0, length as isize, regs, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_search(bufp: *mut RePatternBuffer, string: *const c_char, length: RegoffT, start: RegoffT, range: RegoffT, regs: *mut ReRegisters) -> RegoffT {
    unsafe { search_raw(bufp, string, length as isize, start as isize, range as isize, length as isize, regs, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_match_2(
    bufp: *mut RePatternBuffer,
    string1: *const c_char,
    length1: RegoffT,
    string2: *const c_char,
    length2: RegoffT,
    start: RegoffT,
    regs: *mut ReRegisters,
    stop: RegoffT,
) -> RegoffT {
    unsafe { search_2_raw(bufp, string1, length1 as isize, string2, length2 as isize, start as isize, 0, regs, stop as isize, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_search_2(
    bufp: *mut RePatternBuffer,
    string1: *const c_char,
    length1: RegoffT,
    string2: *const c_char,
    length2: RegoffT,
    start: RegoffT,
    range: RegoffT,
    regs: *mut ReRegisters,
    stop: RegoffT,
) -> RegoffT {
    unsafe { search_2_raw(bufp, string1, length1 as isize, string2, length2 as isize, start as isize, range as isize, regs, stop as isize, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_set_registers(bufp: *mut RePatternBuffer, regs: *mut ReRegisters, num_regs: u32, starts: *mut RegoffT, ends: *mut RegoffT) {
    let p = unsafe { Pattern::from_mut_ptr(bufp) };
    let r = unsafe { Registers::from_mut_ptr_nonnull(regs) };
    unsafe { p.set_registers(r, num_regs, starts, ends) };
}

static RE_COMP_BUF: SyncCell<Pattern> = SyncCell::new(Pattern::ZERO);

fn re_comp_in(b: &mut Pattern, s: Option<&CStr>) -> *mut c_char {
    let Some(s) = s else {
        if b.buffer.is_null() {
            return c"No previous regular expression".as_ptr() as *mut c_char;
        }
        return null_mut();
    };
    if !b.buffer.is_null() {
        b.clear_keep_fastmap();
    }
    if b.fastmap.is_null() && !b.alloc_fastmap() {
        return ERROR_MSGS[REG_ESPACE as usize].as_ptr() as *mut c_char;
    }
    b.set_flag(B_NEWLINE_ANCHOR, true);
    let ret = b.compile(s.to_bytes(), re_syntax_options.load(Ordering::Relaxed));
    if ret == REG_NOERROR { null_mut() } else { ERROR_MSGS[ret as usize].as_ptr() as *mut c_char }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_comp(s: *const c_char) -> *mut c_char {
    let s = unsafe { ffi::cstr(s) };
    unsafe { RE_COMP_BUF.with_unsync(|b| re_comp_in(b, s)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_exec(s: *const c_char) -> c_int {
    (unsafe { regexec(RE_COMP_BUF.as_ptr().cast::<RegexT>(), s, 0, null_mut(), 0) } == 0) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static loc1: AtomicPtr<c_char> = AtomicPtr::new(null_mut());
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static loc2: AtomicPtr<c_char> = AtomicPtr::new(null_mut());
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static locs: AtomicPtr<c_char> = AtomicPtr::new(null_mut());

#[cfg(all(feature = "export", not(feature = "shared")))]
core::arch::global_asm!(
    ".globl __rl_data_loc1",
    ".set __rl_data_loc1, loc1",
    ".symver __rl_data_loc1, loc1@GLIBC_2.2.5",
    ".globl __rl_data_loc2",
    ".set __rl_data_loc2, loc2",
    ".symver __rl_data_loc2, loc2@GLIBC_2.2.5",
    ".globl __rl_data_locs",
    ".set __rl_data_locs, locs",
    ".symver __rl_data_locs, locs@GLIBC_2.2.5",
);

fn expbuf_regex(expbuf: *const c_char) -> *const RegexT {
    let a = core::mem::align_of::<*const RegexT>();
    let p = expbuf as usize + a;
    (p - p % a) as *const RegexT
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn step(string: *const c_char, expbuf: *const c_char) -> c_int {
    let mut m = RegMatch { so: 0, eo: 0 };
    if unsafe { regexec(expbuf_regex(expbuf), string, 1, &mut m, REG_NOTEOL) } == REG_NOMATCH {
        return 0;
    }
    loc1.store(string.wrapping_offset(m.so as isize).cast_mut(), Ordering::Relaxed);
    loc2.store(string.wrapping_offset(m.eo as isize).cast_mut(), Ordering::Relaxed);
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn advance(string: *const c_char, expbuf: *const c_char) -> c_int {
    let mut m = RegMatch { so: 0, eo: 0 };
    if unsafe { regexec(expbuf_regex(expbuf), string, 1, &mut m, REG_NOTEOL) } == REG_NOMATCH || m.so != 0 {
        return 0;
    }
    loc2.store(string.wrapping_offset(m.eo as isize).cast_mut(), Ordering::Relaxed);
    1
}
