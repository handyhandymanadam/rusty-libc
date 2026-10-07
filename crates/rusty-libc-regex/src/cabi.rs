use crate::api::{self, Compiled, MAGIC};
use crate::consts::*;
use crate::exec::Reg;
use crate::vec::V;
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr::{null, null_mut};

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
pub static mut re_syntax_options: c_ulong = 0;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut re_max_failures: c_int = 2000;

unsafe fn compiled<'a>(p: *const RePatternBuffer) -> Option<&'a Compiled> {
    unsafe {
        let b = (*p).buffer as *mut Compiled;
        if b.is_null() || (*p).used == 0 {
            return None;
        }
        if (*b).magic != MAGIC {
            return None;
        }
        Some(&*b)
    }
}

unsafe fn free_compiled(p: *mut RePatternBuffer) {
    unsafe {
        let b = (*p).buffer as *mut Compiled;
        if !b.is_null() && (*p).allocated == core::mem::size_of::<Compiled>() && (*b).magic == MAGIC {
            core::ptr::drop_in_place(b);
            rusty_libc_malloc::free(b.cast());
        }
        (*p).buffer = null_mut();
        (*p).allocated = 0;
    }
}

unsafe fn compile_internal(preg: *mut RePatternBuffer, pattern: *const u8, length: usize, syntax: u64) -> i32 {
    unsafe {
        (*preg).set_flag(B_FASTMAP_ACCURATE | B_NOT_BOL | B_NOT_EOL | B_CAN_BE_NULL, false);
        (*preg).syntax = syntax as c_ulong;
        (*preg).used = 0;
        (*preg).re_nsub = 0;
        (*preg).set_regs_allocated(REGS_UNALLOCATED);
        free_compiled(preg);
        let pat: &[u8] = if length == 0 { &[] } else { core::slice::from_raw_parts(pattern, length) };
        let trans: Option<&[u8; 256]> = if (*preg).translate.is_null() { None } else { Some(&*((*preg).translate as *const [u8; 256])) };
        match api::compile(pat, syntax, trans) {
            Ok(c) => {
                let sz = core::mem::size_of::<Compiled>();
                let mem = rusty_libc_malloc::malloc(sz) as *mut Compiled;
                if mem.is_null() {
                    return REG_ESPACE;
                }
                (*preg).re_nsub = c.nfa.nsub as usize;
                mem.write(c);
                (*preg).buffer = mem.cast();
                (*preg).allocated = sz;
                (*preg).used = sz;
                REG_NOERROR
            }
            Err(e) => {
                (*preg).buffer = null_mut();
                (*preg).allocated = 0;
                e
            }
        }
    }
}

unsafe fn fastmap_in_use<'a>(p: *const RePatternBuffer, start: isize, last_start: isize) -> Option<&'a [u8; 256]> {
    unsafe {
        if !(*p).fastmap.is_null() && (*p).flag(B_FASTMAP_ACCURATE) && start != last_start && !(*p).flag(B_CAN_BE_NULL) {
            Some(&*((*p).fastmap as *const [u8; 256]))
        } else {
            None
        }
    }
}

unsafe fn xlat_for<'a>(preg: *const RePatternBuffer, c: &'a Compiled, buf: &'a mut [u8; 256]) -> &'a [u8; 256] {
    unsafe {
        if (*preg).translate.is_null() {
            &c.xlat
        } else {
            let t = &*((*preg).translate as *const [u8; 256]);
            *buf = api::make_xlat((*preg).syntax & RE_ICASE != 0, Some(t));
            buf
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regcomp(preg: *mut RegexT, pattern: *const c_char, cflags: c_int) -> c_int {
    unsafe {
        let mut syntax = if cflags & REG_EXTENDED != 0 { RE_SYNTAX_POSIX_EXTENDED } else { RE_SYNTAX_POSIX_BASIC };
        (*preg).buffer = null_mut();
        (*preg).allocated = 0;
        (*preg).used = 0;
        (*preg).fastmap = rusty_libc_malloc::malloc(256) as *mut c_char;
        if (*preg).fastmap.is_null() {
            return REG_ESPACE;
        }
        if cflags & REG_ICASE != 0 {
            syntax |= RE_ICASE;
        }
        if cflags & REG_NEWLINE != 0 {
            syntax &= !RE_DOT_NEWLINE;
            syntax |= RE_HAT_LISTS_NOT_NEWLINE;
            (*preg).set_flag(B_NEWLINE_ANCHOR, true);
        } else {
            (*preg).set_flag(B_NEWLINE_ANCHOR, false);
        }
        (*preg).set_flag(B_NO_SUB, cflags & REG_NOSUB != 0);
        (*preg).translate = null_mut();
        let mut ret = compile_internal(preg, pattern.cast(), rusty_libc_mem::strlen(pattern.cast()), syntax);
        if ret == REG_ERPAREN {
            ret = REG_EPAREN;
        }
        if ret == REG_NOERROR {
            re_compile_fastmap(preg);
        } else {
            rusty_libc_malloc::free((*preg).fastmap.cast());
            (*preg).fastmap = null_mut();
        }
        ret
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regerror(errcode: c_int, _preg: *const RegexT, errbuf: *mut c_char, errbuf_size: usize) -> usize {
    unsafe {
        let msg = match error_message(errcode) {
            Some(m) => m,
            None => rusty_libc_core::process::abort(),
        };
        let msg_size = msg.len() + 1;
        if errbuf_size != 0 {
            let mut cpy = msg_size;
            if msg_size > errbuf_size {
                cpy = errbuf_size - 1;
                *errbuf.add(cpy) = 0;
            }
            core::ptr::copy_nonoverlapping(ERROR_MSGS[errcode as usize].as_ptr(), errbuf.cast::<u8>(), cpy);
        }
        msg_size
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regfree(preg: *mut RegexT) {
    unsafe {
        free_compiled(preg);
        if !(*preg).fastmap.is_null() {
            rusty_libc_malloc::free((*preg).fastmap.cast());
        }
        (*preg).fastmap = null_mut();
        if !(*preg).translate.is_null() {
            rusty_libc_malloc::free((*preg).translate.cast());
        }
        (*preg).translate = null_mut();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regexec(preg: *const RegexT, string: *const c_char, nmatch: usize, pmatch: *mut RegMatch, eflags: c_int) -> c_int {
    unsafe {
        if eflags & !(REG_NOTBOL | REG_NOTEOL | REG_STARTEND) != 0 {
            return REG_BADPAT;
        }
        let (start, length): (isize, usize);
        if eflags & REG_STARTEND != 0 {
            let so = (*pmatch).so;
            let eo = (*pmatch).eo;
            if so < 0 || eo < 0 {
                return REG_NOMATCH;
            }
            start = so as isize;
            length = eo as usize;
        } else {
            start = 0;
            length = rusty_libc_mem::strlen(string.cast());
        }
        let c = match compiled(preg) {
            Some(c) => c,
            None => return REG_NOMATCH,
        };
        let text: &[u8] = if length == 0 { &[] } else { core::slice::from_raw_parts(string.cast(), length) };
        let mut xbuf = [0u8; 256];
        let xlat = xlat_for(preg, c, &mut xbuf);
        let (nm, pm): (usize, &mut [Reg]) =
            if (*preg).flag(B_NO_SUB) || nmatch == 0 { (0, &mut []) } else { (nmatch, core::slice::from_raw_parts_mut(pmatch, nmatch)) };
        let fm = fastmap_in_use(preg, start, length as isize);
        let ft = if (*preg).translate.is_null() { None } else { Some(&*((*preg).translate as *const [u8; 256])) };
        let err = api::run(c, xlat, (*preg).flag(B_NEWLINE_ANCHOR), text, start, length as isize, length, eflags, nm, pm, fm, ft);
        (err != REG_NOERROR) as c_int
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_set_syntax(syntax: c_ulong) -> c_ulong {
    unsafe {
        let old = re_syntax_options;
        re_syntax_options = syntax;
        old
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_compile_pattern(pattern: *const c_char, length: usize, bufp: *mut RePatternBuffer) -> *const c_char {
    unsafe {
        (*bufp).set_flag(B_NO_SUB, re_syntax_options & RE_NO_SUB != 0);
        (*bufp).set_flag(B_NEWLINE_ANCHOR, true);
        let ret = compile_internal(bufp, pattern.cast(), length, re_syntax_options);
        if ret == REG_NOERROR { null() } else { ERROR_MSGS[ret as usize].as_ptr().cast() }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_compile_fastmap(bufp: *mut RePatternBuffer) -> c_int {
    unsafe {
        let c = match compiled(bufp) {
            Some(c) => c,
            None => return 0,
        };
        if (*bufp).fastmap.is_null() {
            return 0;
        }
        let mut fm = [0u8; 256];
        let mut cbn = false;
        c.nfa.fastmap((*bufp).syntax & RE_ICASE != 0, &mut fm, &mut cbn);
        core::ptr::copy_nonoverlapping(fm.as_ptr(), (*bufp).fastmap.cast::<u8>(), 256);
        if cbn {
            (*bufp).set_flag(B_CAN_BE_NULL, true);
        }
        (*bufp).set_flag(B_FASTMAP_ACCURATE, true);
        0
    }
}

unsafe fn re_copy_regs(regs: *mut ReRegisters, pmatch: &[Reg], regs_allocated: u32) -> u32 {
    unsafe {
        let nregs = pmatch.len();
        let need = nregs + 1;
        let mut rval = REGS_REALLOCATE;
        if regs_allocated == REGS_UNALLOCATED {
            (*regs).start = rusty_libc_malloc::malloc(need * 4) as *mut RegoffT;
            if (*regs).start.is_null() {
                return REGS_UNALLOCATED;
            }
            (*regs).end = rusty_libc_malloc::malloc(need * 4) as *mut RegoffT;
            if (*regs).end.is_null() {
                rusty_libc_malloc::free((*regs).start.cast());
                return REGS_UNALLOCATED;
            }
            (*regs).num_regs = need as u32;
        } else if regs_allocated == REGS_REALLOCATE {
            if need > (*regs).num_regs as usize {
                let ns = rusty_libc_malloc::realloc((*regs).start.cast(), need * 4) as *mut RegoffT;
                if ns.is_null() {
                    return REGS_UNALLOCATED;
                }
                let ne = rusty_libc_malloc::realloc((*regs).end.cast(), need * 4) as *mut RegoffT;
                if ne.is_null() {
                    rusty_libc_malloc::free(ns.cast());
                    return REGS_UNALLOCATED;
                }
                (*regs).start = ns;
                (*regs).end = ne;
                (*regs).num_regs = need as u32;
            }
        } else {
            rval = REGS_FIXED;
        }
        for (i, r) in pmatch.iter().enumerate() {
            *(*regs).start.add(i) = r.so;
            *(*regs).end.add(i) = r.eo;
        }
        for i in nregs..(*regs).num_regs as usize {
            *(*regs).start.add(i) = -1;
            *(*regs).end.add(i) = -1;
        }
        rval
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn re_search_stub(bufp: *mut RePatternBuffer, string: *const u8, length: isize, start: isize, range: isize, stop: isize, regs: *mut ReRegisters, ret_len: bool) -> RegoffT {
    unsafe {
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
        if (*bufp).flag(B_NOT_BOL) {
            eflags |= REG_NOTBOL;
        }
        if (*bufp).flag(B_NOT_EOL) {
            eflags |= REG_NOTEOL;
        }
        if start < last_start && !(*bufp).fastmap.is_null() && !(*bufp).flag(B_FASTMAP_ACCURATE) {
            re_compile_fastmap(bufp);
        }
        let mut regs = regs;
        if (*bufp).flag(B_NO_SUB) {
            regs = null_mut();
        }
        let nregs: usize;
        if regs.is_null() {
            nregs = 1;
        } else if (*bufp).regs_allocated() == REGS_FIXED && (*regs).num_regs as usize <= (*bufp).re_nsub {
            nregs = (*regs).num_regs as usize;
            if nregs < 1 {
                regs = null_mut();
            }
        } else {
            nregs = (*bufp).re_nsub + 1;
        }
        let nregs = if regs.is_null() { 1 } else { nregs };
        let c = match compiled(bufp) {
            Some(c) => c,
            None => return -1,
        };
        let mut pmatch: V<Reg> = V::from_elem(Reg { so: -1, eo: -1 }, nregs);
        if pmatch.oom {
            return -2;
        }
        let text: &[u8] = if length == 0 { &[] } else { core::slice::from_raw_parts(string, length as usize) };
        let mut xbuf = [0u8; 256];
        let xlat = xlat_for(bufp, c, &mut xbuf);
        let stop = if stop < 0 { 0 } else { stop as usize };
        let fm = fastmap_in_use(bufp, start, last_start);
        let ft = if (*bufp).translate.is_null() { None } else { Some(&*((*bufp).translate as *const [u8; 256])) };
        let result = api::run(c, xlat, (*bufp).flag(B_NEWLINE_ANCHOR), text, start, last_start, stop.min(text.len()), eflags, nregs, &mut pmatch, fm, ft);
        let mut rval: RegoffT = 0;
        if result != REG_NOERROR {
            rval = if result == REG_NOMATCH { -1 } else { -2 };
        } else if !regs.is_null() {
            let ra = re_copy_regs(regs, &pmatch, (*bufp).regs_allocated());
            (*bufp).set_regs_allocated(ra);
            if ra == REGS_UNALLOCATED {
                rval = -2;
            }
        }
        if rval == 0 {
            rval = if ret_len { pmatch[0].eo - start as i32 } else { pmatch[0].so };
        }
        rval
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn re_search_2_stub(
    bufp: *mut RePatternBuffer,
    string1: *const u8,
    length1: isize,
    string2: *const u8,
    length2: isize,
    start: isize,
    range: isize,
    regs: *mut ReRegisters,
    stop: isize,
    ret_len: bool,
) -> RegoffT {
    unsafe {
        if length1 < 0 || length2 < 0 || stop < 0 {
            return -2;
        }
        let len = match length1.checked_add(length2) {
            Some(l) if l <= i32::MAX as isize => l,
            _ => return -2,
        };
        let mut joined: V<u8> = V::new();
        let s: *const u8 = if length2 > 0 {
            if length1 > 0 {
                joined.extend_from_slice(core::slice::from_raw_parts(string1, length1 as usize));
                joined.extend_from_slice(core::slice::from_raw_parts(string2, length2 as usize));
                if joined.oom {
                    return -2;
                }
                joined.as_ptr()
            } else {
                string2
            }
        } else {
            string1
        };
        re_search_stub(bufp, s, len, start, range, stop, regs, ret_len)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_match(bufp: *mut RePatternBuffer, string: *const c_char, length: RegoffT, start: RegoffT, regs: *mut ReRegisters) -> RegoffT {
    unsafe { re_search_stub(bufp, string.cast(), length as isize, start as isize, 0, length as isize, regs, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_search(bufp: *mut RePatternBuffer, string: *const c_char, length: RegoffT, start: RegoffT, range: RegoffT, regs: *mut ReRegisters) -> RegoffT {
    unsafe { re_search_stub(bufp, string.cast(), length as isize, start as isize, range as isize, length as isize, regs, false) }
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
    unsafe { re_search_2_stub(bufp, string1.cast(), length1 as isize, string2.cast(), length2 as isize, start as isize, 0, regs, stop as isize, true) }
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
    unsafe { re_search_2_stub(bufp, string1.cast(), length1 as isize, string2.cast(), length2 as isize, start as isize, range as isize, regs, stop as isize, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_set_registers(bufp: *mut RePatternBuffer, regs: *mut ReRegisters, num_regs: u32, starts: *mut RegoffT, ends: *mut RegoffT) {
    unsafe {
        if num_regs != 0 {
            (*bufp).set_regs_allocated(REGS_REALLOCATE);
            (*regs).num_regs = num_regs;
            (*regs).start = starts;
            (*regs).end = ends;
        } else {
            (*bufp).set_regs_allocated(REGS_UNALLOCATED);
            (*regs).num_regs = 0;
            (*regs).start = null_mut();
            (*regs).end = null_mut();
        }
    }
}

static mut RE_COMP_BUF: RePatternBuffer =
    RePatternBuffer { buffer: null_mut(), allocated: 0, used: 0, syntax: 0, fastmap: null_mut(), translate: null_mut(), re_nsub: 0, bits: 0, _pad: 0 };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_comp(s: *const c_char) -> *mut c_char {
    unsafe {
        let buf = &raw mut RE_COMP_BUF;
        if s.is_null() {
            if (*buf).buffer.is_null() {
                return c"No previous regular expression".as_ptr() as *mut c_char;
            }
            return null_mut();
        }
        if !(*buf).buffer.is_null() {
            let fastmap = (*buf).fastmap;
            (*buf).fastmap = null_mut();
            regfree(buf);
            core::ptr::write_bytes(buf as *mut u8, 0, core::mem::size_of::<RePatternBuffer>());
            (*buf).fastmap = fastmap;
        }
        if (*buf).fastmap.is_null() {
            (*buf).fastmap = rusty_libc_malloc::malloc(256) as *mut c_char;
            if (*buf).fastmap.is_null() {
                return ERROR_MSGS[REG_ESPACE as usize].as_ptr() as *mut c_char;
            }
        }
        (*buf).set_flag(B_NEWLINE_ANCHOR, true);
        let ret = compile_internal(buf, s.cast(), rusty_libc_mem::strlen(s.cast()), re_syntax_options);
        if ret == REG_NOERROR { null_mut() } else { ERROR_MSGS[ret as usize].as_ptr() as *mut c_char }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_exec(s: *const c_char) -> c_int {
    unsafe { (regexec(&raw const RE_COMP_BUF, s, 0, null_mut(), 0) == 0) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut loc1: *mut c_char = null_mut();
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut loc2: *mut c_char = null_mut();
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut locs: *mut c_char = null_mut();

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
    unsafe {
        let mut m = RegMatch { so: 0, eo: 0 };
        if regexec(expbuf_regex(expbuf), string, 1, &mut m, REG_NOTEOL) == REG_NOMATCH {
            return 0;
        }
        loc1 = string.offset(m.so as isize) as *mut c_char;
        loc2 = string.offset(m.eo as isize) as *mut c_char;
        1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn advance(string: *const c_char, expbuf: *const c_char) -> c_int {
    unsafe {
        let mut m = RegMatch { so: 0, eo: 0 };
        if regexec(expbuf_regex(expbuf), string, 1, &mut m, REG_NOTEOL) == REG_NOMATCH || m.so != 0 {
            return 0;
        }
        loc2 = string.offset(m.eo as isize) as *mut c_char;
        1
    }
}

#[allow(dead_code)]
fn _unused(_: *mut c_void) {}
